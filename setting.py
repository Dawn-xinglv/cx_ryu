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
            cur.execute('SELECT id,dpid,mac from mac_to_port where dpid=? and mac=? ', (row[0],row[1]))  # 查询某个dpid,mac是否存在，port可能会变，需要更新
            row_exist = cur.fetchone()            
#            print 'row_exist:', row_exist
            if row_exist == None:    # add 
                cur.execute('''insert into mac_to_port(dpid, mac, port, time) values(?, ?, ?, datetime('now','localtime'))''', row) 
            else:   # update port
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
    print 'mac_to_port_items:', mac_to_port_items
    for dpid,mac,port in mac_to_port_items:
        mac_to_port.setdefault(dpid, {}) 
        mac_to_port[dpid][mac] = port  
#    print 'mac_to_port:', mac_to_port
    
    conn.commit()    #提交，如果不提交，关闭连接后所有更改都会丢失
    conn.close()
    print 'read from database <mac_to_port> table successfully'
    
    return mac_to_port
    
    
    
    