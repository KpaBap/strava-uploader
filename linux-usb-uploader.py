from pyudev import Context, Monitor, MonitorObserver
import re, glob, time

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
    
    
    


    

observer = MonitorObserver(monitor, callback=find_garmin, name='monitor-observer')
observer.daemon = False

observer.start()
