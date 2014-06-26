from pyudev import Context, Monitor, MonitorObserver
import re, glob, time, json, urllib.request, cherrypy, threading, sqlite3, sys

def startup():
    strava_client_secret = "2ddc808e59ae9d4532235f78cf72fa7da9fa649d"
    strava_client_id = "1451"
    web_port = 9090

    observer = MonitorObserver(monitor, callback=find_garmin, name='monitor-observer')
    observer.daemon = True
    observer.start()

    request_json.token = strava_get_token()

    if not request_json.token:
        ##Disable cherrypy logging to stdout, bind to all IPs, start in a separate thread
        cherrypy.log.screen=False
        cherrypy.server.socket_host = "0.0.0.0"

        cherrypy.server.socket_port = web_port

        thread = threading.Thread(target=cherrypy.quickstart, args=(Root(),))
        thread.start()


context = Context()
monitor = Monitor.from_netlink(context)
monitor.filter_by(subsystem='block')

def find_garmin(device):
    fit_dir=False

    try:
        if device.attributes['partition'] == b"1":
            partition = device.sys_name
            

            for parent_dev in device.ancestors:
                try:
                    model = parent_dev.attributes['model']
                    if model == b'Edge 800 SD Card':
                        print("Edge 800 SD card partition found: %s" % partition)
                        print("Waiting for the slow ass Garmin to get mounted", end="",flush=True)

                        time_start = time.time()

                        while(fit_dir==False):
                            print('.',end="",flush=True)    
                            fit_dir = find_fits(partition)
                            if time.time() - time_start > 45:
                                print("timed out!")
                                break
                            else:
                                time.sleep(1)
                            
                        
    
                    if fit_dir:
                        print ("\nFound .fit directory: %s" % fit_dir)
                        return
                except:
                    pass
    except:
        return False


def find_fits(partition):
    re_mnt = re.compile("%s\s(.*?)\s" % partition)
    
    garmin_path = "/Garmin/Activities/"

    try:
        mtab = open("/proc/mounts").read()
        mountpoint = re_mnt.search(mtab).group(1)
    except:
        #print("Failed to find mount point for: %s" % partition)
        return False
    
    try:
        fitfile = glob.glob(mountpoint + garmin_path + "*.fit")[0]
        return mountpoint+garmin_path
    except:
        #print("Did not find any .fit files on: %s" % mountpoint + garmin_path)
        return False
    
    
    

def request_json(url):
    headers = {'Authorization': 'access_token ' + request_json.token}
    req = urllib.request.Request(url, None, headers)
    response = urllib.request.urlopen(req)
    response = json.loads(response.read().decode('utf-8'))
    return response

def strava_insert_token(token):
    """ Insert a user's strava token into the token table """
    conn = sqlite3.connect('strava.sqlite')
    c = conn.cursor()
    query = "INSERT INTO tokens VALUES (:token)"
    c.execute(query, {'token': token})
    conn.commit()
    c.close()

def strava_get_token():
    """ Get an token by user """
    conn = sqlite3.connect('strava.sqlite')
    c = conn.cursor()
    query = "SELECT token FROM tokens"
    
    try:
        result = c.execute(query).fetchone()
    except:
        return False
    if (result):
        c.close()
        return result[0]
    else:
        c.close()
        return False
    
def strava_delete_token(token):
    """ Delete a user's token from the token table """
    conn = sqlite3.connect('strava.sqlite')
    c = conn.cursor()
    query = "DELETE FROM tokens WHERE token = :token"
    c.execute(query, {'token': token})
    conn.commit()
    c.close()


class Root:
    @cherrypy.expose
    def strava_request_access(self):
        return """
                You've reached the Strava answering machine, leave a message after the beep.
                """


def main_loop():
    startup()
    while 1:
        time.sleep(0.1)

if __name__ == "__main__":
    try: 
        main_loop()
    except KeyboardInterrupt:
        sys.exit(0)
