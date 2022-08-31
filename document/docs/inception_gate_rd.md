#Inception Gate开发者手册
##背景
Inception Gate是一款专门用来解决MySQL数据库异构数据实时同步问题的工具，目前，业界有两种这方面的需求：

1. 对数据库表的更新做异构化，也就是将上层数据库表结构及存储方式不能满足应用需求，需要转换、数据清洗及提取等，存储到另一种表结构中，这种存储方式更适合应用程序访问计算等。
2. 针对一些统计业务，每天都需要对某些表做统计，一般是在hadoop中计算，基于目前的方案，每天都需要大量的对MySQL数据库做全量数据的查询，先存储到hadoop中，然后才能计算，这样既浪费了很多时间，又对业务数据库产生影响，更重要的是，在数据库表日益增长的同时，每天查一次全量已经完全不能满足需求，增量又很难获取到，所以这就需要有一款异构实时数据同步的工具来解决这样的问题，这样统计可以随时进行，同时不会对业务数据库产生影响，完美解决问题。

##架构介绍
![](inception_images/inception_transfer_arch.png)
Inception Gate的实现方式和MySQL数据库主从是同一个道理，Inception Gate会伪装成一个从库，从主库上面dump指定的binlog，Inception Gate收到之后，将其解析出来，直接在线转换成为一种更通用的，其它程序也能解析的Json格式，然后再存储到MySQL中，这个MySQL就是上图中所示的DC（datacenter）。

Inception Gate写入DC的方式是远程插入，是做为DC的客户端插入进去的。这种情况下，开发同学，只需要关注DC数据库即可，查出来的数据，都是增量的更新，其需要解析Json，然后应用到对应的统计库或者异构库中，即可实现数据库的异构实时同步，不过完全实时是不可能的，只需要保证Inception Gate在复制时没有延迟，同时应用程序读取DC的数据尽可能的快就好。

在上面复制架构中，每一个复制，都是一个单独并且完全独立的通道，但是不同的通道，可以对应同一个数据库实例，那么在每新建一个通道时，都需要给对应的通道起一个名字，这个名字指的就是这个通道对应的DC名，在这个数据库实例中，其实就是一个数据库名字，那么多个通道时，这个数据库实例中，就会有多个数据库，Incpetion Gate会将所有拿到的Binlog解析后存储到各自对应的DC中。

##表结构介绍
上面已经提到，开发同学，只需要关注DC数据库中的数据即可，而DC指的是一个数据库，一个通道，那么这个数据库中，有什么表是需要开发同学关注的呢？

只有两个
###transfer_data
````
CREATE TABLE `transfer_data` (
  `id` bigint(20) unsigned NOT NULL COMMENT 'id but not auto increment',
  `tid` bigint(20) unsigned NOT NULL COMMENT 'transaction id',
  `dbname` varchar(64) DEFAULT NULL COMMENT 'dbname',
  `tablename` varchar(64) DEFAULT NULL COMMENT 'tablename',
  `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'the create time of event ',
  `instance_name` varchar(64) DEFAULT NULL COMMENT 'the source instance of this event',
  `optype` varchar(64) DEFAULT NULL COMMENT 'operation type, include insert, update...',
  `data` longtext COMMENT 'binlog transfer data, format json',
  PRIMARY KEY (`id`,`tid`),
  KEY `idx_dbtablename` (`dbname`,`tablename`),
  KEY `idx_create_time` (`create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='binlog transfer data'
````

下面分别介绍每一个列的细节：

1. ID，这个列存储的是一个序号，但不是MySQL的自增ID，是Inception Gate自己维护的一个自增序号，每读一个Binlog事件，序号就加1，因为每一个事务是一个Binlog的原子单元，Inception Gate在存储时，也是以事件为单位的。维护一个这样的ID，主要是为了与另一个列TID一起来做联系主键使用的，因为Binlog在文件中是有序的，而插入到transfer_data中之后（如果是并发插入的话），如果没有这个联系主键的话，很难保证实际的顺序，同时这也是为开发同学提供的一个自己维护的游标信息，在具体使用过程中，开发同学需要自己来维护这两个ID值，这样才能知道异构数据已经同步到什么位置了。
2. TID，上面已经介绍了一部分，这个值是与Binlog中的事务相关的，每次开始一个新事务，这个值就加1，也就是说，在transfer_data表中，不同数据中，如果TID的值相同的话，说明这些变更是同一个事务产生的，但是ID值肯定是不同的。
3. DBNAME，这个列存储的是当前变更发生在哪个库中，与另一个列TABLENAME一起，用来表示当前变更是针对哪一个表的，因为ROW模式Binlog中，每一个事件只能是针对一个表的操作，所以想要知道某一个表发生了哪些变化，或者统计应用如果只关注某些表，或者某一个表的话，只需要不断的查询这些表对应的变更即可。同时表transfer_data中，已经建了这两个列的联系索引，性能应该是不成问题的。
4. TABLENAME：上面已经介绍过了。
5. CREATE_TIME：这个列，是用来存储，当前Binlog事件实际在主库上面执行的时间值，这个时间，应用程序也可以用来检查当前处理是不是有延迟，或者延迟多少等。
6. INSTANCE_NAME：这个列用来存储当前DC是从哪个实例上面获取的Binlog，存储格式是IP加端口，用“：”分隔。应用程序如果关注切换的话，如果发现这个值变了，则说明切换了，那么此时有可能存在数据冗余处理，因为Inception Gate在处理切换时，不可能精确的找到原来读取Binlog的数据库实例失败的位置与Inception Gate设置的从节点的位置，只能是通过CREATE_TIME的值来确认不丢Binlog即可，找到比CREATE_TIME值小的最大的值，然后从其对应的Binlog位置开始继续复制即可。（高可用自动切换的实现方式是，在配置DC复制时，会同时配置一个备用节点，在复制过程中，Inception Gate会不断的取当前备用节点的unix_timestamp及show master status;，当发生切换时，通过create_time与unix_timestamp的对比，找到对应的show master status值）。
7. OPTYPE：这个列存储当前事件的操作类型，目前包括INSERT、UPDATE、DELETE、TRUNCATE、ALTERTABLE、RENAME、CREATETABLE。应用程序需要哪一种变更，就处理哪一种，否则可以直接忽略或者不查即可。
8. DATA，这个列，就是这个表的主角了，这里面存储的就是某一个Binlog事件，在翻译之后的信息，它的类型为大字段，内容格式为Json的。

###transfer_checkpoint
````
CREATE TABLE `transfer_checkpoint` (
  `id` bigint(20) unsigned NOT NULL COMMENT 'eid',
  `tid` bigint(20) unsigned NOT NULL COMMENT 'tid'
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='checkpoint sequence, 
                                    before which are all avialable'
````
因为Inception Gate转换线上Binlog，是多线程并发处理的，那么肯定存在一个问题，就是最新被处理的Binlog有可能是不完整的，存在空洞，因为线程通过操作系统内核调度时执行有先有后，最新执行的事务前面经常会存在还没有执行的事务，而此时最新的事务已经插入到DC中了，而没有执行的当然在DC中不会有，那么如果应用程序读的太快的话，就会导致有些数据读不到，因为应用程序已经认为读过的位置之前的事务都已经读取完毕了。那这样就导致了数据丢失的问题。

而这个表就是用来解决这个问题的，在DC中，没办法知道在什么位置之前所有的数据都是完整的，而Inception Gate是了如指掌的，所以通过这个表，来精确记录这个分界点的位置。

从表结构可以很明确的看到，只存储了两个id值，这两个id值就是对应transfer_data中的id值，只不过这个表告诉你，在transfer_data表中，所有小于这两个id值的数据，都是完整的，不会丢失数据，而大于这两个值的数据，则事务之间存在空洞的问题。而同时，这个表只会有一条记录。

简单而言，在应用程序使用过程中，只要把这个表中的id值记录为当前可以读取的最大位置即可。

##JSON内容介绍
在上面提到的DATA列中，针对不同的optype，DATA列的Json键有所区分，下面分别介绍：

###INSERT，DELETE，UPDATE
针对DML语句，Json内容区别在于，新数据使用NEW为键，值为一个数组，每一个元素又是一个字典，字典中每一个列（变更数据表）名为键，对应的值为字典的值。老数据（删除或者更新之后的）使用OLD为键，值与上面是一样的。下面是一个更新操作的例子：
````
{
    "OLD": [
        {
            "id": "13581311"
        },
        {
            "hotel_id": "10826108"
        },
        {
            "from_date": "2016-01-12"
        },
        {
            "to_date": "2016-04-11"
        },
        {
            "status": "0"
        },
        {
            "update_time": "2016-01-12 14:12:32"
        },
        {
            "wrapper_ids": ""
        },
        {
            "priority": "0"
        }
    ],
    "NEW": [
        {
            "id": "13581311"
        },
        {
            "hotel_id": "10826108"
        },
        {
            "from_date": "2016-01-12"
        },
        {
            "to_date": "2016-04-11"
        },
        {
            "status": "1"
        },
        {
            "update_time": "2016-01-12 19:02:16"
        },
        {
            "wrapper_ids": ""
        },
        {
            "priority": "0"
        }
    ]
}
````
###TRUNCATE
对于TRUNCATE类型的操作，DATA列是空的，没有任何数据。
###ALTERTABLE
对于ALTER表的操作，JSON内容如下：
````
{
    "ADDCOLUMN": [
        {
            "field_name": "age",
            "data_type": "INT"
        }
    ],
    "ADDINDEX": [
        {
            "index_name": "idx_name_sno",
            "column_name": [
                "name",
                "sno"
            ]
        }
    ],
    "DROPCOLUMN": [
        "grade"
    ],
    "CHANGECOLUMN": [
        {
            "origin_field_name": "name",
            "field_name": "name",
            "data_type": "VARCHAR(64)"
        }
    ],
    "DROPINDEX": [
        "idx_sno"
    ],
    "OTHERS": "Be ignored or nothing"
}
````
需要说明的是，在改表操作中，一般关注的是比较重要的几个，上面基本已经列出来了，其它比较细小的变化就被忽略了，正如上面OTHERS表示的：Be ignored or nothing。

###RENAME
对于重命的操作，Json内容如下：
````
{
    "RENAME": [
        {
            "from": {
                "dbname": "test",
                "tablename": "t"
            },
            "to": {
                "dbname": "test",
                "tablename": "tnew"
            }
        }
    ]
}
````
###CREATETABLE
对于建表操作，显示的信息比较全面，包括列名，是否可以为空，是不是主键列及数据类型，下面是一个简单的建表例子：
````
{
    "NEW": [
        {
            "field_name": "sno",
            "nullable": "Yes",
            "primary_key": "No",
            "data_type": "int(11)"
        },
        {
            "field_name": "name",
            "nullable": "Yes",
            "primary_key": "No",
            "data_type": "varchar(100)"
        }
    ]
}
````

##注意事项
1. 有这样的需求时，请联系DBA，为大家分配datacenter，然后会告诉你需要访问的IP端口及库名等信息。
2. Inception Gate处理的是增量，那么最初的基准数据，可能需要通过时间来划分，对数据准确性（开始位置）不高的，可以直接从某个时间开始然后取增量即可，对于要求高的，需要DBA备份一份数据，然后开发同学将其转换为自己需要的统计库，然后再从备份数据的位置开始同步增量即可。
3. 使用方式上面，都可以随心所欲，如果只想要某几个表的增量，可以要求DBA在创建的时候，设置白名单，或者如果不要哪些表，可以设置黑名单，在处理增量时，为了尽可能的减少数据复制延迟，可以根据自己的业务特点，通过分表创建多线程（库表有联合索引），各自处理不同表的数据即可，如果对数据的一致性要求比较高，可以分库做多线程等等。
4. 在使用过程中有任何问题，请联系DBA王竹峰。

