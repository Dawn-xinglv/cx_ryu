#!/usr/bin/python
#coding=utf-8

import sqlite3

if __name__=='__main__':
    conn = sqlite3.connect('sfc_db.sqlite')
    cur = conn.cursor()
    
#    print "Opened database successfully"
#    print('创建一张表websites...')
#    cur.execute('''create table websites(id integer primary key not null,
#                                         name text,
#                                         url  text)''')                  #创建表
#
#    cur.execute('insert into websites(name,url)values("谷歌","http://www.google.com")')    #插入
#    cur.execute('insert into websites(name,url)values("百度","http://www.baidu.com")') 
#    cur.execute('insert into websites(name,url)values("淘宝","http://www.taobao.com")') 
#    cur.execute('insert into websites(name,url)values("新浪","http://www.sina.com")') 
    
#    cur.execute('DELETE from biao where id=4')                          #删除
#    print('显示所有记录...')
#    temp=cur.execute('SELECT id,name,passwd from biao')                 #显示
#    for row in temp:
#        print 'id=',row[0]
#        print 'name=',row[1]
#        print 'passwd=',row[2],'\n'
#    print 'Operation done successfully'

#    cur.execute('''create table sfc(id integer primary key autoincrement not null,
#                            sfc_nsh_spi INTEGER,
#                            sfc_nsh_si INTEGER,
#                            src TEXT,
#					 dst TEXT,
#					 sf1 TEXT,
#					 sf2 TEXT,
#					 sf3 TEXT,
#					 sf4 TEXT,
#					 sf5 TEXT
#					 )''')                  #创建表

#    cur.execute('insert into sfc(sfc_nsh_spi,sfc_nsh_si,src,dst,sf1,sf2)values(1,255,"192.168.2.100","192.168.2.200","firewall","dpi")')    #插入

#    cur.execute('''create table vnf_ip(id integer primary key autoincrement not null,
#                            vnf TEXT,
#					 ip TEXT
#					 )''') 

#    cur.execute('DELETE from sfc where id=1')                          #删除
#    cur.execute('insert into sfc(sfc_nsh_spi,sfc_nsh_si,src,dst,sf1)values(2,255,"192.168.2.100","192.168.2.201","192.168.2.50")')    #插入

#    cur.execute('''create table sfc_path(id integer primary key autoincrement not null,
#                            sfc_nsh_spi INTEGER,
#                            classifier INTEGER,
#                            switch1 INTEGER,
#                            switch2 INTEGER,
#                            switch3 INTEGER,
#                            switch4 INTEGER,
#                            switch5 INTEGER,
#                            switch6 INTEGER,
#                            switch7 INTEGER,
#                            switch8 INTEGER,
#                            switch9 INTEGER,
#                            switch10 INTEGER
#					 )''') 

#    cur.execute('insert into sfc_path(sfc_nsh_spi,classifier,switch1,switch2,switch3)values(1,2,3,4,5)')    #插入
#    cur.execute('insert into sfc_path(sfc_nsh_spi,classifier,switch1,switch2,switch3,switch4)values(2,2,6,7,8,9)')    #插入

# ppt topo
#    cur.execute('insert into sfc(sfc_nsh_spi,sfc_nsh_si,src,dst,sf1,sf2)values(1,255,"192.168.2.101","192.168.2.200","192.168.2.30","192.168.2.40")')    #插入
#    cur.execute('insert into sfc(sfc_nsh_spi,sfc_nsh_si,src,dst,sf1,sf2)values(2,255,"192.168.2.102","192.168.2.200","192.168.2.30","192.168.2.40")') 

#    cur.execute('insert into sfc(sfc_nsh_spi,sfc_nsh_si,src,dst,sf1,sf2)values(3,255,"192.168.20.22","192.168.20.21","192.168.20.33","192.168.20.43")')    #插入
#    cur.execute('insert into sfc_path(sfc_nsh_spi,classifier,switch1,switch2,switch3,switch4,switch5,switch6)values(3,2,6,3,6,4,6,2)')


    # 将self.mac_to_port写入数据库
#    mac_to_port = {2: {'00:00:00:00:00:03': 2, '00:00:00:00:00:01': 3}, 
#                   3: {'00:00:00:00:00:03': 3, '00:00:00:00:00:01': 2}, 
#                   4: {'00:00:00:00:00:01': 1}, 
#                   5: {'00:00:00:00:00:01': 1}, 
#                   6: {'00:00:00:00:00:01': 1}, 
#                   7: {'00:00:00:00:00:03': 2, '00:00:00:00:00:01': 1}}
#
#    mac_to_port_items = mac_to_port.items()  # 把字典变成列表，元素变成元组
#    print('mac_to_port_items:%r\n' % mac_to_port_items)  # mac_to_port_items:[(2, {'00:00:00:00:00:03': 2, '00:00:00:00:00:01': 3}), (3, {'00:00:00:00:00:03': 3, '00:00:00:00:00:01': 2}), (4, {'00:00:00:00:00:01': 1}), (5, {'00:00:00:00:00:01': 1}), (6, {'00:00:00:00:00:01': 1}), (7, {'00:00:00:00:00:03': 2, '00:00:00:00:00:01': 1})]
#    
#    row = []   # single line data
#    for outer_data in mac_to_port_items:     # outer_data -> tuple
#        inner_items = outer_data[1].items()  # inner_items -> list
#        for inner_data in inner_items:       # inner_data -> tuple
#            row.append(outer_data[0])        # dpid
#            row.append(inner_data[0])        # mac
#            row.append(inner_data[1])        # port
#            cur.execute('SELECT id,dpid,mac from mac_to_port where dpid=? and mac=? ', (row[0],row[1]))  # 查询某个dpid,mac是否存在，port可能会变，需要更新
#            row_exist = cur.fetchone()            
#            print 'row_exist:', row_exist
#            if row_exist == None:    # add 
#                cur.execute('''insert into mac_to_port(dpid, mac, port, time) values(?, ?, ?, datetime('now','localtime'))''', row) 
#            else:   # update port
#                cur.execute('''update mac_to_port set port=?, time=datetime('now','localtime') where id=? ''', (row[2],row_exist[0])) 
#            print 'row:', row
#            row = []   # clean
            
    
    # 从数据库读self.mac_to_port
#    mac_to_port = {} 
#    cur.execute('SELECT dpid,mac,port from mac_to_port')  # 
#    mac_to_port_items = cur.fetchall()  # data:list
#    print 'mac_to_port_items:', mac_to_port_items
#    for dpid,mac,port in mac_to_port_items:
#        print 'dpid:', dpid
#        print 'mac:', mac
#        print 'port:', port
#        mac_to_port.setdefault(dpid, {}) 
#        mac_to_port[dpid][mac] = port  
#        
#    print 'mac_to_port:', mac_to_port
    
    
    # 将self.link_to_port写入数据库
#    link_to_port = {(2, 7): (2, 1), (7, 3): (2, 2), (4, 7): (2, 3), (2, 6): (1, 1), 
#                    (4, 6): (1, 3), (6, 3): (2, 1), (5, 6): (1, 4), (5, 7): (2, 4), 
#                    (7, 4): (3, 2), (7, 5): (4, 2), (6, 5): (4, 1), (3, 6): (1, 2), 
#                    (6, 2): (1, 1), (3, 7): (2, 2), (6, 4): (3, 1), (7, 2): (1, 2)}
#
#    link_to_port_items = link_to_port.items()  # 把字典变成列表，元素变成元组
#    print('link_to_port_items:%r\n' % link_to_port_items) # link_to_port_items:[((2, 7), (2, 1)), ((7, 3), (2, 2)), ((4, 7), (2, 3)), ((2, 6), (1, 1)), ((4, 6), (1, 3)), ((6, 4), (3, 1)), ((5, 6), (1, 4)), ((5, 7), (2, 4)), ((7, 4), (3, 2)), ((6, 3), (2, 1)), ((7, 5), (4, 2)), ((7, 2), (1, 2)), ((3, 6), (1, 2)), ((6, 2), (1, 1)), ((3, 7), (2, 2)), ((6, 5), (4, 1))]
#
#    row = []   # single line data
#    for outer_data in link_to_port_items:    # outer_data -> tuple, outer_data: ((2, 7), (2, 1))
##        print 'outer_data:', outer_data
#        inner_keys = outer_data[0]           # inner_keys -> tuple, inner_keys: (2, 7)
##        print 'inner_keys:', inner_keys
#        inner_values = outer_data[1]         # inner_values -> tuple, inner_values: (2, 1)
##        print 'inner_values:', inner_values
#
#        row.append(inner_keys[0])          # src_dpid
#        row.append(inner_keys[1])          # dst_dpid
#        row.append(inner_values[0])        # src_port
#        row.append(inner_values[1])        # dst_port
#        cur.execute('SELECT * from link_to_port where src_dpid=? and dst_dpid=? ', (row[0],row[1]))  # 查询某一对dpid是否存在，注意port可能会变，比如把网线插到另一个端口，所以port需要更新
#        row_exist = cur.fetchone()            
#        print 'row_exist:', row_exist
#        if row_exist == None:    # add 
#            cur.execute('''insert into link_to_port(src_dpid, dst_dpid, src_port, dst_port, time) values(?, ?, ?, ?, datetime('now','localtime'))''', row) 
#        else:   # update port
#            cur.execute('''update link_to_port set src_port=?, dst_port=?, time=datetime('now','localtime') where id=? ''', (row[2],row[3],row_exist[0]))
#        print 'row:', row
#        row = []   # clean    
    
    
    # 从数据库读self.link_to_port
#    link_to_port = {} 
#    cur.execute('SELECT src_dpid,dst_dpid,src_port,dst_port from link_to_port')
#    link_to_port_items = cur.fetchall()  # link_to_port_items:list, link_to_port_items: [(2, 7, 2, 1), (7, 3, 2, 2), (4, 7, 2, 3), (2, 6, 1, 1), (4, 6, 1, 3), (6, 4, 3, 1), (5, 6, 1, 4), (5, 7, 2, 4), (7, 4, 3, 2), (6, 3, 2, 1), (7, 5, 4, 2), (7, 2, 1, 2), (3, 6, 1, 2), (6, 2, 1, 1), (3, 7, 2, 2), (6, 5, 4, 1)]
#    print 'link_to_port_items:', link_to_port_items
#    for src_dpid,dst_dpid,src_port,dst_port in link_to_port_items:
##        print 'src_dpid:', src_dpid
##        print 'dst_dpid:', dst_dpid
##        print 'src_port:', src_port
##        print 'dst_port:', dst_port
#        link_to_port[(src_dpid, dst_dpid)] = (src_port, dst_port)      
#    print 'link_to_port:', link_to_port
    
    
    # 将self.pre_path写入数据库
#    pre_path = [3,6,4,7]  # 长度不固定
#    
#    temp = map(str,pre_path)  
#    row = ','.join(temp)   # row:string  '3,6,4'
#    print 'row:', row
#    
#    cur.execute('SELECT * from pre_path') #查询数据库中的pre_path
#    row_exist = cur.fetchone() 
#    print 'row_exist:', row_exist
#    if row_exist == None:    # add 
#        cur.execute('''insert into pre_path(pre_path) values(?)''', (row,))
#    else:  # not none
#        row_exist = list(row_exist)
#        print 'row_exist[0]:', row_exist[0]
#        if row != row_exist[0]:  # update
#            cur.execute('''update pre_path set pre_path=?''', (row,))

    #从数据库读self.pre_path
    pre_path = []
    cur.execute('SELECT * from pre_path') 
    temp = cur.fetchone()   
    print 'temp:', temp
    pre_path_str = temp[0]
#    print 'pre_path_str:', pre_path_str
    pre_path = pre_path_str.split(',')
#    print 'pre_path:', pre_path
    pre_path = map(int, pre_path)
    print 'pre_path:', pre_path
    
    
    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
   
