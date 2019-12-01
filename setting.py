# coding=utf-8

import sqlite3


# Common Setting for Network awareness module.
DISCOVERY_PERIOD = 10   			# For discovering topology.
MONITOR_PERIOD = 10			     # For monitoring traffic
DELAY_DETECTING_PERIOD = 5			# For detecting link delay.
TOSHOW = True					# For showing information in terminal
MAX_CAPACITY = 281474976710655L		# Max capacity of link


# database function
def write_to_database_mac_to_port(data):
    conn = sqlite3.connect('sfc_db.sqlite')   # open database
    cur = conn.cursor()
    
    mac_to_port_items = data.items()         # 把字典变成列表，元素变成元组
    row = []   # single line data
    for outer_data in mac_to_port_items:     # outer_data: tuple
        inner_items = outer_data[1].items()  # inner_items: list
        for inner_data in inner_items:       # inner_data: tuple
            row.append(outer_data[0])        # dpid
            row.append(inner_data[0])        # mac
            row.append(inner_data[1])        # port
            cur.execute('SELECT id,dpid,mac,port from mac_to_port where dpid=? and mac=? ', (row[0],row[1]))  # 查询某个dpid,mac是否存在，port可能会变，需要更新
            row_exist = cur.fetchone()            
#            print 'row_exist:', row_exist
            if row_exist == None:    # add 
                cur.execute('''insert into mac_to_port(dpid, mac, port, time) values(?, ?, ?, datetime('now','localtime'))''', row) 
            else:   # not none
                if row[2] != row_exist[3]:  # update port
                    cur.execute('''update mac_to_port set port=?, time=datetime('now','localtime') where id=? ''', (row[2],row_exist[0])) 
#            print 'row:', row
            row = []   # clean   
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()     # close database
    print 'write to database <mac_to_port> table successfully'

def read_from_database_mac_to_port():
    conn = sqlite3.connect('sfc_db.sqlite')   # open database
    cur = conn.cursor()
    
    mac_to_port = {} 
    cur.execute('SELECT dpid,mac,port from mac_to_port')  # 
    mac_to_port_items = cur.fetchall()  # mac_to_port_items:list
#    print 'mac_to_port_items:', mac_to_port_items
    for dpid,mac,port in mac_to_port_items:
        mac_to_port.setdefault(dpid, {}) 
        mac_to_port[dpid][mac] = port  
#    print 'mac_to_port:', mac_to_port
    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
    print 'read from database <mac_to_port> table successfully'
    return mac_to_port
    
def write_to_database_link_to_port(data):
    conn = sqlite3.connect('sfc_db.sqlite')   # open database
    cur = conn.cursor()
    
    link_to_port_items = data.items()  # 把字典变成列表，元素变成元组
#    print('link_to_port_items:%r\n' % link_to_port_items) # link_to_port_items:[((2, 7), (2, 1)), ((7, 3), (2, 2)), ((4, 7), (2, 3)), ((2, 6), (1, 1)), ((4, 6), (1, 3)), ((6, 4), (3, 1)), ((5, 6), (1, 4)), ((5, 7), (2, 4)), ((7, 4), (3, 2)), ((6, 3), (2, 1)), ((7, 5), (4, 2)), ((7, 2), (1, 2)), ((3, 6), (1, 2)), ((6, 2), (1, 1)), ((3, 7), (2, 2)), ((6, 5), (4, 1))]

    row = []   # single line data
    for outer_data in link_to_port_items:    # outer_data -> tuple, outer_data: ((2, 7), (2, 1))
#        print 'outer_data:', outer_data
        inner_keys = outer_data[0]           # inner_keys -> tuple, inner_keys: (2, 7)
#        print 'inner_keys:', inner_keys
        inner_values = outer_data[1]         # inner_values -> tuple, inner_values: (2, 1)
#        print 'inner_values:', inner_values

        row.append(inner_keys[0])          # src_dpid
        row.append(inner_keys[1])          # dst_dpid
        row.append(inner_values[0])        # src_port
        row.append(inner_values[1])        # dst_port
        cur.execute('SELECT id,src_dpid,dst_dpid,src_port,dst_port from link_to_port where src_dpid=? and dst_dpid=? ', (row[0],row[1]))  # 查询某一对dpid是否存在，注意port可能会变，比如把网线插到另一个端口，所以port需要更新
        row_exist = cur.fetchone()            
#        print 'row_exist:', row_exist
        if row_exist == None:    # add 
            cur.execute('''insert into link_to_port(src_dpid, dst_dpid, src_port, dst_port, time) values(?, ?, ?, ?, datetime('now','localtime'))''', row) 
        else:   # not none
            if row[2] != row_exist[3] or row[3] != row_exist[4]:   # update port
                cur.execute('''update link_to_port set src_port=?, dst_port=?, time=datetime('now','localtime') where id=? ''', (row[2],row[3],row_exist[0]))
#        print 'row:', row
        row = []   # clean    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
    print 'write to database <link_to_port> table successfully'
    
def read_from_database_link_to_port():
    conn = sqlite3.connect('sfc_db.sqlite')   # open database
    cur = conn.cursor()
    
    link_to_port = {} 
    cur.execute('SELECT src_dpid,dst_dpid,src_port,dst_port from link_to_port')
    link_to_port_items = cur.fetchall()  # link_to_port_items:list, link_to_port_items: [(2, 7, 2, 1), (7, 3, 2, 2), (4, 7, 2, 3), (2, 6, 1, 1), (4, 6, 1, 3), (6, 4, 3, 1), (5, 6, 1, 4), (5, 7, 2, 4), (7, 4, 3, 2), (6, 3, 2, 1), (7, 5, 4, 2), (7, 2, 1, 2), (3, 6, 1, 2), (6, 2, 1, 1), (3, 7, 2, 2), (6, 5, 4, 1)]
#    print 'link_to_port_items:', link_to_port_items
    for src_dpid,dst_dpid,src_port,dst_port in link_to_port_items:
#        print 'src_dpid:', src_dpid
#        print 'dst_dpid:', dst_dpid
#        print 'src_port:', src_port
#        print 'dst_port:', dst_port
        link_to_port[(src_dpid, dst_dpid)] = (src_port, dst_port)
        
#    print 'link_to_port:', link_to_port
    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
    print 'read from database <link_to_port> table successfully'
    return link_to_port
    
  
def write_to_database_pre_path(data):
    conn = sqlite3.connect('sfc_db.sqlite')   # open database
    cur = conn.cursor()  
    
    temp = map(str,data)
    row = ','.join(temp)   # row:string  '3,6,4'
#    print 'row:', row
    
    cur.execute('SELECT * from pre_path') #查询数据库中的pre_path
    row_exist = cur.fetchone() 
#    print 'row_exist:', row_exist
    if row_exist == None:    # add 
        cur.execute('''insert into pre_path(pre_path) values(?)''', (row,))
    else:  # not none
        row_exist = list(row_exist)
#        print 'row_exist[0]:', row_exist[0]
        if row != row_exist[0]:  # update
            cur.execute('''update pre_path set pre_path=?''', (row,))
    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
    print 'write to database <pre_path> table successfully'
    
    
def read_from_database_pre_path():
    conn = sqlite3.connect('sfc_db.sqlite')   # open database
    cur = conn.cursor()
    
    pre_path = []
    cur.execute('SELECT * from pre_path') 
    temp = cur.fetchone()   
#    print 'temp:', temp
    pre_path_str = temp[0]
#    print 'pre_path_str:', pre_path_str
    pre_path = pre_path_str.split(',')
#    print 'pre_path:', pre_path
    pre_path = map(int, pre_path)
#    print 'pre_path:', pre_path
    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
    print 'read from database <pre_path> table successfully'
    return pre_path
    
    
    
    
    
    