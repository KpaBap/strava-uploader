from pyudev import Context, Monitor, MonitorObserver
import re, glob, time, json, urllib.request, urllib.parse, cherrypy, threading, sqlite3, sys, webbrowser, os, requests, subprocess

def startup():
    strava_client_secret = "1234abcde"
    strava_client_id = "0"
    web_port = 9090

    sys.stdout = simpleLogger("strava-upload.log")
    sys.stderr = simpleLogger("strava-upload-errors.log")

    upload_fits.token = strava_get_token()

    if not upload_fits.token:
        strava_oauth_exchange(strava_client_secret,strava_client_id, web_port)
        check_strava_token(strava_get_token())
    else:
        check_strava_token(strava_get_token())
        
    #If we get this far either something went wrong or we got a token from Strava
    upload_fits.token = strava_get_token()
    start_udev_monitoring()

def check_strava_token(token):
    url = "https://www.strava.com/api/v3/athlete"

    try:
        headers = {'Authorization': 'Bearer ' + token}
        req = urllib.request.Request(url, None, headers)
        response = urllib.request.urlopen(req)
        response = json.loads(response.read().decode('utf-8'))
        return True
    except:
        print("Current Strava token is invalid. Removing database file. Please restart the script and try again.")
        os.unlink("stravatoken.sqlite")
        sys.exit(0)


        
def start_udev_monitoring():
    #Setting up Linux UDEV monitoring in a separate thread
    context = Context()
    monitor = Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block')
    observer = MonitorObserver(monitor, callback=find_garmin, name='monitor-observer')
    observer.daemon = True
    observer.start()
    #End UDEV init

def strava_oauth_exchange(strava_client_secret,strava_client_id, web_port):
    strava_check_create_tables()
    #Send the user off to Strava to authorize us and start local webserver
    strava_oauth_url = "https://www.strava.com/oauth/authorize?client_id=%s&response_type=code&redirect_uri=http://localhost:%s/strava_token_exchange&scope=write&approval_prompt=auto" % (strava_client_id, web_port)
    webbrowser.open_new_tab(strava_oauth_url)

    ##Disable cherrypy logging to stdout, bind to all IPs, start in a separate thread
    cherrypy.engine.autoreload.on = False
    cherrypy.log.screen=False
    cherrypy.server.socket_host = "0.0.0.0"
    cherrypy.server.socket_port = web_port
    cherrypy.quickstart(webServer(strava_client_secret,strava_client_id))


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
                        print("Waiting for the slow ass Garmin to get mounted")
                        #Attempt to mount the SDCARD partition and keep trying to find the .fit files
                        #Doing this in a loop because the SDCARD may get auto mounted before we mount it 
                        #We keep checking if the .fit files exist regardless of how it got mounted
                        while(fit_dir==False):                            
                            fit_dir = find_fits(partition) 
                            try:
                                if mount_sdcard(partition):   
                                    fit_dir = find_fits(partition)                             
                                    break

                            except:
                                raise
                            else:
                                time.sleep(1)

                    if fit_dir:
                        print ("Found .fit directory: %s" % fit_dir)
                        print ("Using Strava token: %s" % upload_fits.token)
                        upload_fits(fit_dir, partition)
                        return
                except:
                    pass
    except:
        return False

def mount_sdcard(partition):
    tmpdir = '/tmp/strava-upload-sdcard'

    if not os.path.exists(tmpdir):
        print("Creating temporary mount directory")
        mkdir_result = subprocess.call(['mkdir %s' % tmpdir], shell=True)
        if mkdir_result != 0:
            print ("Failed to create directory: %s" % tmpdir)
            return False
        
    print ("Attempting to mount SDCARD partition (%s)" % partition)
    mount_result = subprocess.call(['mount /dev/%s %s' % (partition, tmpdir)], shell=True)
    if mount_result != 0:
        print ("Failed to mount /dev/%s - probably don't have permissions to" % partition)
        return False

    return True
    
        

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
    
    
    

def strava_check_create_tables():
    """ Create tables for the database, these should always be up to date """
    conn = sqlite3.connect('stravatoken.sqlite')
    c = conn.cursor()
    tables = {
        'tokens': "CREATE TABLE tokens (token TEXT UNIQUE ON CONFLICT REPLACE)"
    }
    # Go through each table and check if it exists, if it doesn't, run the SQL statement to create it.
    for (table_name, sql_statement) in tables.items():
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"
        if not c.execute(query, {'table_name': table_name}).fetchone():
            # Run the command.
            c.execute(sql_statement)
            conn.commit()
    c.close()





def strava_get_token():
    """ Get an token by user """
    conn = sqlite3.connect('stravatoken.sqlite')
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
    conn = sqlite3.connect('stravatoken.sqlite')
    c = conn.cursor()
    query = "DELETE FROM tokens WHERE token = :token"
    c.execute(query, {'token': token})
    conn.commit()
    c.close()

# Web server stuff
class webServer:

    def __init__(self,strava_client_secret, strava_client_id): #Get the strava client ID/secrets for the Oauth exchange later
        self.strava_client_secret = strava_client_secret
        self.strava_client_id = strava_client_id
    
    @cherrypy.expose
    def strava_token_exchange(self,state=None,code=None):
        if code:
            params = urllib.parse.urlencode({'client_id': self.strava_client_id, 'client_secret': self.strava_client_secret, 'code': code})
            params = params.encode('utf-8')
            
            req = urllib.request.Request("https://www.strava.com/oauth/token")
            req.add_header("Content-Type","application/x-www-form-urlencoded;charset=utf-8")

            try:
                response = urllib.request.urlopen(req,params)
                response = json.loads(response.read().decode('utf-8'))

                self.strava_insert_token(response['access_token'])

                cherrypy.engine.exit()
                return "Token exchange completed successfully. Shutting down the web service. You can close this window now."
            except:
                cherrypy.engine.exit()
                return "Token exchange with Strava failed. Restart the script and try again."
                
            
        else:
            cherrypy.engine.exit()
            return "Invalid or empty access code received from Strava. Restart the script and try again."
            
    #strava_token_exchange._cp_config = {'response.stream': True}

    def strava_insert_token(self,token):
        """ Insert a user's strava token into the token table """
        conn = sqlite3.connect('stravatoken.sqlite')
        c = conn.cursor()
        query = "INSERT INTO tokens VALUES (:token)"
        c.execute(query, {'token': token})
        conn.commit()
        c.close()
# End Web server stuff


def store_filename(filename):
    conn = sqlite3.connect('uploads.sqlite')
    c = conn.cursor()
    result = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='uploads';").fetchone()
    if not result:
        c.execute('''create table uploads(filename text)''')

    c.execute("INSERT INTO uploads VALUES (?)" , [filename])
    conn.commit()
    conn.close()

def hasbeen_uploaded(filename):
    conn = sqlite3.connect('uploads.sqlite')
    c = conn.cursor()
    result = len(c.execute("SELECT filename FROM uploads WHERE filename = ?", (filename,)).fetchall())

    if result > 0:    
        return True
    else:
        return False
    
 
def upload_fits(fit_dir, partition):
    
    skipped = 0
    upload_files = []
    
    fitfiles = glob.glob("%s/*.fit" % fit_dir)
 
    for fitfile in fitfiles:
        if not hasbeen_uploaded(os.path.basename(fitfile)):
            upload_files.append(fitfile)
        else:
            skipped +=1
            
    if len(upload_files)>0:
        
        for fitfile in upload_files:
            upload_id, filename = upload_fit_file(upload_fits.token, fitfile)
            if upload_id:
                thread = threading.Thread(target=get_upload_status, args=(upload_fits.token,upload_id, filename))
                thread.start()
        while threading.activeCount() > 2: # wait for all files to finish processing
            pass

    else: #nothing to upload
        print ("Nothing to upload.")
    
    print ("%s files skipped." % skipped)
    #unmount the SD card partition
    print ("Unmounting SD card: /dev/%s" % partition)
    unmount_result = subprocess.call(['umount /dev/%s' % partition], shell=True)
    if mount_result != 0:
        print ("Failed to unmount /dev/%s - probably don't have permissions to" % partition)       


def upload_fit_file(token, fitfile):

    fitdata = open(fitfile,"rb").read()

    headers = {'Authorization': 'Bearer ' + token}
    data = {'file': (fitfile, fitdata), "data_type": (None,"fit")}
    
    try:
        res= requests.post("http://www.strava.com/api/v3/uploads", files=data, headers=headers)

        
        upload_id = res.json()['id']
        print("Uploaded file: %s" % fitfile)
    except:
        print("There was an error uploading the file")
        print(traceback.format_exc())
        return False, fitfile
    
    return upload_id, fitfile


def get_upload_status(token, upload_id, filename):
    start_time = time.time()
    while 1:
        headers = {'Authorization': 'Bearer ' + token}
        res = requests.get("https://www.strava.com/api/v3/uploads/%s" % upload_id, headers=headers)
        status = res.json()['status']
        error = res.json()['error']
        
        if error:
            print("Error: %s" % error)
            if error.find("duplicate") != -1:
                store_filename(os.path.basename(filename))
            return
        elif status == "Your activity is ready.":
            
            store_filename(os.path.basename(filename))
        
            print("%s successfully uploaded and processed in %s seconds." % (os.path.basename(filename),round(time.time()-start_time,2)))
            return
        
        time.sleep(1)

#override print function to add timestamps
def print(s, **kwargs):
    __builtins__.print(time.strftime("[%b %d %H:%M:%S] ") + s, **kwargs)

class simpleLogger():
    
    def __init__(self,logfile):
        self.logfile = logfile
        open(logfile,"w").write("") ##clear out any previous contents
    
    def write(self,logtext):
        logfile = open(self.logfile,"a")
        logfile.write(logtext)
        logfile.close()
        return 0
    
    def flush(self):
        return 0



def main_loop():
    startup()
    while 1:
        time.sleep(0.1)

if __name__ == "__main__":
    try: 
        main_loop()
    except KeyboardInterrupt:
        sys.exit(0)
