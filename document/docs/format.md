#Inception 格式化语句
这里介绍的是sql格式化功能，该功能主要是将上层传来的sql语句格式化成inception认为的标准sql语句。连接数据库与否或者表是否存在基本对该功能的使用无影响（唯一影响请看参数inception_format_Sql_full_path介绍）。

如果这是你的需求，请继续往下看。

##结果集信息

前面在介绍<<**Inception支持选项及意义**>>中已经讲过了，可以通过设置选项--enable-format来启用格式化语句的功能，同样的，它与其它enable（--enable-parameterize除外）开头的选项是互斥的，不能同时设置，开启之后，再连接Inception，执行返回的结果集包括的列如下：

1. ID：这个用来表示当前语句的一个序列值。
1. Error_Flag：这个列用来表示执行格式化过程中是否出现错误。
1. Error_Message：这个列用来表示执行格式化过程中出现错误的错误信息。
1. Origin_SQL：这个列存储的是上层传来的源sql语句。
1. Format_SQL：这个列存储的是inception格式化后的sql语句。

##举例说明

SQL语句：
````
use test;
select id from aaa where id in  (select id from bbb) and name='lily';
````
执行结果如下： 
````
['ID', 'Error_Flag', 'Error_Message', 'Origin_SQL', 'Format_SQL']
1 | 0 | None | set names utf8mb4 | SET NAMES 'utf8mb4'
2 | 0 | None | select id from aaa where id in  (select id from bbb) and name='lily' | SELECT id FROM test.aaa WHERE id IN (SELECT id FROM test.bbb) AND name="lily"
````
常量变?的执行结果如下:
```
['ID', 'Error_Flag', 'Error_Message', 'Origin_SQL', 'Format_SQL']
1 | 0 | None | set names utf8mb4 | SET NAMES 'utf8mb4'
2 | 0 | None | select id from aaa where id in  (select id from bbb) and name='lily' | SELECT id FROM test.aaa WHERE id IN (SELECT id FROM test.bbb) AND name=?
```

如果需要打印字段名为db.table.column_name形式，则需要在执行设置inception_format_Sql_full_path＝1，如下：

````
......
conn=MySQLdb.connect(host='127.0.0.1',user='xxxx',passwd='xxxx',db='test',port=9998)
cur=conn.cursor()
cur.execute('inception set session inception_format_Sql_full_path=1')
ret=cur.execute(要执行的sql)
result=cur.fetchall()
......
````
执行结果如下：
````
['ID', 'Error_Flag', 'Error_Message', 'Origin_SQL', 'Format_SQL']
1 | 0 | None | set names utf8mb4 | SET NAMES 'utf8mb4'
2 | 0 | None | select id from aaa where id in  (select id from bbb) and name='lily' | SELECT test.aaa.id FROM test.aaa WHERE test.aaa.id IN (SELECT test.bbb.id FROM test.bbb) AND test.aaa.name="lily"
````

注：python脚本与之前基本一样，只是enable部分换成--enable-format即可。如果需要将常量变成?形式，则需要在--enable-format后设置--enable-parameterize即可。

上面的SQL语句只是举个例子，目前可以进行格式化的sql类型有select，update，delete和insert。

##后记
这个功能目前可能会存在某些表达式不支持的情况，还需要后期的不断完善及更新，请各位有兴趣的同学，有任何意见、建议，都可以加群或者联系本人QQ讨论解决。

