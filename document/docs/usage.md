#Inception使用方法
Inception实际上是一个服务程序，那么它应该有自己的一套友好的使用方式，必须要具备简单、高效、易用等特性。那么为了让Inception具有这些特点，在设计之初，就规定了它的使用方式，如下所述。

通过Inception对语句进行审核时，必须要告诉Inception这些语句对应的数据库地址、数据库端口以及Inception连接数据库时使用的用户名、密码等信息，而不能简单的只是执行一条sql语句，所以必须要通过某种方式将这些信息传达给Inception。而我们选择的方式是，为了不影响语句的意义，将这些必要信息都以注释的方式放在语句最前面，也就是说所有这些信息都是被
/\*\*/括起来的，每一个参数都是通过分号来分隔，类似的方式为：  
`/*--user=username;--password=xxxx;--host=127.0.0.1;--port=3306;*/`  
当然支持的参数不止是这几个，后面还会介绍一些其它的参数。
Inception要做的是一个语句块的审核，需要引入一个规则，将要执行的语句包围起来，Inception规定，在语句的最开始位置，要加上`inception_magic_start;`语句，在执行语句块的最后加上`inception_magic_commit;`语句，这2个语句在 Inception 中都是合法的、具有标记性质的可被正确解析的 SQL 语句。被包围起来的所有需要审核或者执行的语句都必须要在每条之后加上分号，其实就是批量执行SQL语句。（包括 `use database`语句之后也要加分号，这点与 MySQL 客户端不同），不然存在语法错误。

在具体执行时，在没有解析到**inception_magic_start**之前如果发现要执行其它的语句，则直接报错，因为规则中**inception_magic_start**是强制的。而如果在执行的语句块最后没有出现**inception_magic_commit**，则直接报错，不会做任何操作。
在前面注释部分，需要指定一些操作的选项，包括线上用户名、密码、数据库地址、检查/执行等，下面是一个简单的例子：  
````
/*--user=zhufeng;--password=xxxxxxxxxxx;--host=xxxxxxxxxx;
--enable-check;--port=3456;*/  
inception_magic_start;  
use mysql;  
CREATE TABLE adaptive_office(id int);  
inception_magic_commit;
````
------------------
**注意：下面说明非常重要，请认真看**  
那么上面这一段就是一批正常可以执行的SQL语句，目前执行**只支持通过C/C++接口、Python接口来对Inception访问**，这一段必须是**一次性**的通过执行接口提交给Inception，那么在处理完成之后，Inception会返回一个结果集，来告诉我们这些语句中存在什么错误，或者是完全正常等等。  

请不要将下面的SQL语句块，放到MySQL客户端中执行，因为这是一个自动化运维工具，如果使用交互式的命令行来使用的话没有意义，只能是通过写程序来访问Inception服务器。

而可以通过MySQL客户端来执行的，只有是Inception命令，请参考<<**inception命令集语句**>>一节。

下面是一段执行上面语句的Python程序的例子：

-----------------
````python
\#!/usr/bin/python
\#-\*-coding: utf-8-\*-
import MySQLdb
sql='/*--user=username;--password=password;--host=127.0.0.1;--execute=1;--port=3306;*/\
inception_magic_start;\
use mysql;\
CREATE TABLE adaptive_office(id int);\
inception_magic_commit;'
try:
    conn=MySQLdb.connect(host='127.0.0.1',user='',passwd='',db='',port=9998)
    cur=conn.cursor()
    ret=cur.execute(sql)
    result=cur.fetchall()
    num_fields = len(cur.description) 
    field_names = [i[0] for i in cur.description]
    print field_names
    for row in result:
        print row[0], "|",row[1],"|",row[2],"|",row[3],"|",row[4],"|",
		row[5],"|",row[6],"|",row[7],"|",row[8],"|",row[9],"|",row[10]
    cur.close()
    conn.close()
except MySQLdb.Error,e:
     print "Mysql Error %d: %s" % (e.args[0], e.args[1])
````

执行这段程序之后，返回的结果如下：  
````
['ID', 'stage', 'errlevel', 'stagestatus', 'errormessage', 'SQL', 'Affected_rows', 
'sequence', 'backup_dbname', 'execute_time', 'sqlsha1']  
1 | CHECKED | 0 | Audit completed | None | use mysql | 0 | '0_0_0' | None |     0  |
2 | CHECKED | 1 | Audit completed | Set engine to innodb for table 'adaptive_office'.  
Set charset to one of 'utf8mb4' for table 'adaptive_office'.  
Set comments for table 'adaptive_office'.  
Column 'id' in table 'adaptive_office' have no comments.  
Column 'id' in table 'adaptive_office' is not allowed to been nullable.  
Set Default value for column 'id' in table 'adaptive_office'  
Set a primary key for table 'adaptive_office'. | CREATE TABLE adaptive_office(id int) 
| 0 | '0_0_1' | 127_0_0_1_3306_mysql |     0|
````

从返回结果可以看到，每一行语句的审核及执行信息，最前面打印的是field_names，表示Inception的返回结果集的列名信息，总共包括十个列，下面是每个列对应的结果，因为只有两个语句，则只有两行，从结果集第一个列看到只有序号为1和2的两行，而对于每一个列的具体含义，这会在<<**Inception结果集**>>这一章中讲到，这里只看清楚是什么内容即可。

**注意**：最后一个“|”后面其实是存储列sqlsha1的，但这里没有改表语句，所以都是空，关于这个信息，请看<<**Inception结果集**>>一章及<<**Inception 对OSC的支持**>>一章中相关说明。


-------------

**需要注意的是**，在注释中指定的数据库服务器，必须要有Inception访问它的权限，不然Inception会返回没有访问权限的错误。

