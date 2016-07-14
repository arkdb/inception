#Inception所支持的参数变量
考虑到不同用户的规范会有所不同，Inception支持很多可配置的参数，这些配置参数都是全局参数，因为对于同一个服务的规则，不应该经常变化，或者说不应该出现一些业务是这样的规则，而另一些业务是那样的规则，所以这些变量一经设置，就影响所有的审核。如果确实一个公司有多个规则，则建议配置多套Inception服务，在各自的配置文件中指定相应的参数的值。

设置或者打印这些变量的值，可以通过MySQL客户端连接到Inception服务器，通过新的语法命令来实现。连接Inception的时候，只需要指定Inception的地址及端口即可，其它用户名密码可以不指定，因为Inception没有权限验证的过程。

Inception打印变量时，不支持像原来的MySQL服务器一样可以**`show variables like ‘%name%’`**这样实现模糊匹配，只能是精确匹配，如果找不到则返回空结果集，或者可以打印所有变量。语法如下：

----
|支持语句  |	意义		|
|:----------|:--------------------|
|inception get variables ‘variable_name’;	|通过variable_name指定变量名称，只显示指定的变量名的值|
|inception get variables;	|显示Inception所有变量的值|
|inception set variable_name=value;	|设置变量名为variable_name的变量的值|   

-----
Inception目前所支持的变量参数如下表所示：

-----------------
|参数名字                                 	 |可选参数        	 |默认值    	 |功能说明|  
|:-------------------------------------------------|:-----------------------|:---------------:|:-----------|
|inception_check_insert_field             	 |ON/OFF          	 |ON        	 |是不是要检查插入语句中的列链表的存在性|  
|inception_check_dml_where                	 |ON/OFF          	 |ON        	 |在DML语句中没有WHERE条件时，是不是要报错|  
|inception_check_dml_limit                	 |ON/OFF          	 |ON        	 |在DML语句中使用了LIMIT时，是不是要报错|  
|inception_check_dml_orderby              	 |ON/OFF          	 |ON        	 |在DML语句中使用了Order By时，是不是要报错|  
|inception_enable_select_star             	 |ON/OFF          	 |ON        	 |Select*时是不是要报错|  
|inception_enable_orderby_rand            	 |ON/OFF          	 |ON        	 |order by rand时是不是报错|  
|inception_enable_nullable                	 |ON/OFF          	 |ON        	 |创建或者新增列时如果列为NULL，是不是报错|  
|inception_enable_foreign_key             	 |ON/OFF          	 |ON        	 |是不是支持外键|  
|inception_max_key_parts                  	 |1-64            	 |5         	 |一个索引中，列的最大个数，超过这个数目则报错|  
|inception_max_update_rows                	 |1-MAX           	 |10000     	 |在一个修改语句中，预计影响的最大行数，超过这个数就报错|  
|inception_max_keys                       	 |1-1024          	 |16        	 |一个表中，最大的索引数目，超过这个数则报错|  
|inception_enable_not_innodb              	 |ON/OFF          	 |OFF       	 |建表指定的存储引擎不为Innodb，不报错|  
|inception_support_charset                	 |MySQL支持字符集 	 |"utf8mb4" 	 |表示在建表或者建库时支持的字符集，如果需要多个，则用逗号分隔，影响的范围是建表、设置会话字符集、修改表字符集属性等|  
|inception_check_table_comment            	 |ON/OFF          	 |ON        	 |建表时，表没有注释时报错|  
|inception_check_column_comment           	 |ON/OFF          	 |ON        	 |建表时，列没有注释时报错|  
|inception_check_primary_key              	 |ON/OFF          	 |On        	 |建表时，如果没有主键，则报错|  
|inception_enable_partition_table         	 |ON/OFF          	 |OFF       	 |是不是支持分区表|  
|inception_enable_enum_set_bit            	 |ON/OFF          	 |OFF       	 |是不是支持enum,set,bit数据类型|  
|inception_check_index_prefix             	 |ON/OFF          	 |ON            |是不是要检查索引名字前缀为"idx_"，检查唯一索引前缀是不是"uniq_"|  
|inception_enable_autoincrement_unsigned  	 |ON/OFF          	 |ON        	 |自增列是不是要为无符号型|  
|inception_max_char_length                	 |1-MAX           	 |16        	 |当char类型的长度大于这个值时，就提示将其转换为VARCHAR|  
|inception_check_autoincrement_init_value 	 |ON/OFF          	 |ON        	 |当建表时自增列的值指定的不为1，则报错|  
|inception_check_autoincrement_datatype   	 |ON/OFF          	 |ON        	 |当建表时自增列的类型不为int或者bigint时报错|  
|inception_check_timestamp_default        	 |ON/OFF          	 |ON        	 |建表时，如果没有为timestamp类型指定默认值，则报错|  
|inception_enable_column_charset          	 |ON/OFF          	 |OFF       	 |允许列自己设置字符集|  
|inception_check_autoincrement_name       	 |ON/OFF          	 |ON        	 |建表时，如果指定的自增列的名字不为ID，则报错，说明是有意义的，给提示|  
|inception_merge_alter_table              	 |ON/OFF          	 |ON        	 |在多个改同一个表的语句出现是，报错，提示合成一个|  
|inception_check_column_default_value     	 |ON/OFF          	 |ON        	 |检查在建表、修改列、新增列时，新的列属性是不是要有默认值|  
|inception_enable_blob_type               	 |ON/OFF          	 |ON        	 |检查是不是支持BLOB字段，包括建表、修改列、新增列操作|  
|inception_enable_identifer_keyword		|ON/OFF			|OFF		|检查在SQL语句中，是不是有标识符被写成MySQL的关键字，默认值为报警。|
|auto_commit|ON/OFF|OFF|这个参数的作用是为了匹配Python客户端每次自动设置auto_commit=0的，如果取消则会报错，针对Inception本身没有实际意义|
|bind_address|string|*|这个参数实际上就是MySQL数据库原来的参数，因为Incpetion没有权限验证过程，那么为了实现更安全的访问，可以给Inception服务器的这个参数设置某台机器（Inception上层的应用程序）不地址，这样其它非法程序是不可访问的，那么再加上Inception执行的选项中的用户名密码，对MySQL就更加安全|
|general_log|ON/OFF|ON|这个参数就是原生的MySQL的参数，用来记录在Inception服务上执行过哪些语句，用来定位一些问题等|
|general_log_file|string|inception.log|设置general log写入的文件路径|
|inception_user|string|empty|这个用户名在配置之后，在连接Inception的选项中可以不指定user，这样线上数据库的用户名及密码就可以不暴露了，可以做为临时使用的一种方式，但这个用户现在只能是用来审核，也就是说，即使在选项中指定--enable-execute，也不能执行，这个是只能用来审核的帐号。|
|inception_password|string|empty|与上面的参数是一对，这个参数对应的是选项中的password，设置这个参数之后，可以在选项中不指定password|
|inception_enable_sql_statistic|ON/OFF|ON|设置是不是支持统计Inception执行过的语句中，各种语句分别占多大比例，如果打开这个参数，则每次执行的情况都会在备份数据库实例中的inception库的statistic表中以一条记录存储这次操作的统计情况，每次操作对应一条记录，这条记录中含有的信息是各种类型的语句执行次数情况，具体的信息需要参考后面一章<<**Inception 的统计功能**>>|
|inception_read_only|ON/OFF|OFF|设置当前Inception服务器是不是只读的，这是为了防止一些人具有修改权限的帐号时，通过Inception误修改一些数据，如果inception_read_only设置为ON，则即使开了enable-execute，同时又有执行权限，也不会去执行，审核完成即返回|
|inception_check_identifier|ON/OFF|ON|打开与关闭Inception对SQL语句中各种名字的检查，如果设置为ON，则如果发现名字中存在除数字、字母、下划线之外的字符时，会报Identifier "invalidname" is invalid, valid options: [a-z,A-Z,0-9,_].|

-------

#注意事项
上面已经说了，可以用MySQL客户端通过命令`inception get variables;`查看Inception支持的所有参数变量，所有以inception开头的参数，都是专门为Inception加的，而其它的则大都是MySQL原生的，大部分没有任何作用的都已经去除了，有些则没有，这个在使用过程中可着情处理。
而以inception开头的参数中，还有一部分是以inception_osc开头的，这十几个参数主要是用来控制Inception使用OSC工具来执行ALTER表操作时使用的，这部分会在后面一章<<**Inception 对OSC的支持**>>中详细叙述。
