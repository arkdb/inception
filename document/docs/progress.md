#Inception执行进度控制
在Inception上线及使用以来，有时候会碰到一些问题，让DBA很为难，比如执行过程中，Inception挂了，再比如，执行过程中，前端调度程序，与Inception之间网络中断，导致会话结束不能取到执行结果集，这种情况下，如果要恢复执行，DBA首先要对面的问题就是如何快速的找到任务执行的最新位置，找到之后，可以选择从这个位置开始继续执行，当然执行方式就要看前端怎么去做了。

但这里我想要说的是，如何解决找位置的问题，因为Inception没有给前端报出任何关系位置的信息，一般的做法就是到线上去，一条条的核对看有没有执行过，为了加快速度，可以通过二分法，当然这个可想而知，效率并不高，因为首先需要懂得二分法查找原理。

考虑到即使用二分法，效率也不高，所以通过Inception内部来控制一下进度，实际上是可以的，并且只有Inception才是最清楚最新执行到哪的。

Inception的解决方法是，在每次执行一条语句前，向Inception备份库的某个表更新一条记录，用来表示Inception要开始执行某条语句了，状态更新为PREPARE，而在执行完成之后，再次更新这条记录，然后状态更新为Done，那么一个任务对应这么一条进度记录，那如果一个任务失败了，就可以找到最新的位置及对应的语句的状态。

对应的表结构如下：
````
CREATE TABLE `execute_progress` (
  `task_sequence` varchar(128) NOT NULL,
  `sequence` int(11) NOT NULL DEFAULT '0',
  `status` varchar(64) NOT NULL DEFAULT '',
  `update_time` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `errcode` int(11) DEFAULT NULL,
  `message` varchar(1024) DEFAULT NULL,
  `dbname` varchar(128) DEFAULT NULL COMMENT 'current dbname env',
  PRIMARY KEY (`task_sequence`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
````

这个表，像其它备份回滚表一样，是Inception自动创建的，每个列的意义如下：

1. task_sequence：表示当前任务唯一的识别序列号，这个是由前端应用传给Inception的，通过新增选项--sequence来指定，如果指定了这个选项，则有这个进度控制的功能，否则就没有了。这个序列号的唯一性要在前端应用程序中控制，比如通过时间，执行语句块的MD5值等等计算一个HASH值出来，然后通过选项--sequence传入进来，这样Inception在执行过程中，就会使用这个序列号来控制当前任务的执行进度。
2. sequence：表示当前任务中，已经处理到第几条语句了，计数从1开始，这个其实就是用来真正控制进度的信息，他唯一对应一条语句，如果出问题了，就会根据这个序列号来找到任务中的语句，然后做进一步处理。
3. status：这个列是用来控制序列号为sequence的语句的最新状态的，包括PREPARE、DONE及ERROR三种状态，PREPARE表示当前语句已经开始执行，但不知道有没有结束，如果处在这个状态下，则需要DBA人工确认是不是已经执行完成，这是唯一需要DBA做的事情，如果执行了，则从下一条语句开始继续处理，如果没有执行，则从这条语句开始继续处理；如果状态为DONE，那么这就毫无疑问了，当前语句肯定执行完了，而下一条语句还没有开始（因为如果开始了，则状态就是序列号为：sequence+1，状态为PREPARE了），这直接从下一条开始继续处理即可。而如果状态是ERROR，这个就很明确了，这条语句执行错误，可以通过错误信息直接判断从什么位置开始执行了，当然这个和结果集中如果出现执行错误的处理方法是一样的。
4. update_time：一个最新更新的时间值而已，没有其它太多的意义。
5. errcode：如果状态为ERROR，则这个列表示的是错误时的错误码。
6. message：如果状态为ERROR，则这个列表示的是错误信息。
7. dbname：用来表示当前状态的语句在上下文环境中，处于哪个数据库，只针对use 语句设置的情况，如果没有使用use，则这个列为空字符串。这个列的意义在于，如果出现问题了，则很容易的找到了当前语句是在什么库下面操作的，用来快速判断及检验。

下图中所示为线上例子：
````
mysql> select * from execute_progress limit 2\G
*************************** 1. row ***************************
task_sequence: 006ab9c0-a357-49d8-8587-7488e439bc12_1_0
     sequence: 0
       status: DONE
  update_time: 2016-09-06 11:26:11
      errcode: 0
      message: NULL
       dbname: NULL
*************************** 2. row ***************************
task_sequence: 00dd8580-f15d-4f51-8af8-6860feda81e1_1_0
     sequence: 0
       status: DONE
  update_time: 2016-09-09 20:28:33
      errcode: 0
      message: NULL
       dbname: NULL
2 rows in set (0.00 sec)
````

但是，还存在一个问题，假如前端应用程序与Inception失联了，没有取到结果集，而Inception还正在执行一个语句，因为还没有执行到判断连接断了的时机，所以还在继续执行，那此时前端拿到这个任务进度之后，按照不同状态来处理这个任务，但它不知道的是这个任务还在执行，这样是不对的，可能会造成数据的不一致。

这个问题需要通过在Inception内部做一个任务缓存，通过对选项--sequence的值来做唯一性标识，在前端应用程序每次处理一个任务的失败时，都首先连接Inception查询这个任务的缓存情况，可以通过下面的语法来得到存活状态：
````
inception get process status 'feadf1bc-4ebc-419a-997e-28d0135cff9b_1_0';
````
得到的结果是：
````
mysql> inception get process status 'feadf1bc-4ebc-419a-997e-28d0135cff9b_1_0';
+---------+
| STATUS  |
+---------+
| STOPPED |
+---------+
1 row in set (0.00 sec)
````

这个结果集只有一个列，值有两个，包括“STOPPED”及“RUNNING”，很明显，如果是RUNNING的话，则说明这个任务还在跑着，就不能做进一步处理，而如果是STOPPED了，则说明可以做失败处理了。

功能开启需要满足以下条件：

1. 使用--sequence选项
2. 打开数据库备份功能

