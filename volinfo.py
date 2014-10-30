import sys
import pprint
import volatility.plugins.fileparam
import volatility.conf as conf
import volatility.debug as debug
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.protos as protos
import volatility.obj as obj
import volatility.plugins.filescan as filescan
import volatility.plugins.modscan as modscan
import volatility.plugins.sockscan as sockscan
import volatility.plugins.evtlogs as evtlogs
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.registry.hivelist as hivelist

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
except ImportError:
    pass

class VolInfo():
    def __init__(self, config=conf.ConfObject(), deb=debug, *args): 
        self.add_registry(config, deb)
        if self._config.LOCATION:
            self._db = self.initializeDB()
            self._processes = self.get_pslist()
            self._threads = self.get_threadlist()
            self._modules = self.get_modulelist()
            self._sockets = self.get_netlist()
            self._services = self.get_svclist()
            self._hives = self.get_registrylist()
            self.createDB()
        else:
            self._debug.error("Please specify the target image (or try -h)")


    def __del__(self):
        try:
            self._db.close()
        except AttributeError:
            pass

    def add_registry(self, config, deb):
        self._config = config #conf.ConfObject()
        self._debug = deb
        self._debug.setup()
        registry.PluginImporter()
        registry.register_global_options(self._config, commands.Command)
        registry.register_global_options(self._config, addrspace.BaseAddressSpace)
        self._config.add_option('ENABLEDB', short_option='e', 
                                default=False, action='store_true',
                                help='Enable database storage for reuse purpose')   
        self._config.add_option('DBPATH', short_option='m', default='mongodb://localhost:27017', 
                                help='Specify mongodb connection url', 
                                action='store', type='str')
        self._config.parse_options()
        self._debug.setup(self._config.DEBUG)
        self._filename = self._config.FILENAME
        
    def initializeDB(self):
        try:
            if self._config.ENABLEDB:
                self._dbname = self._config.LOCATION.split("/")[-1].split(".")[0]
                db = MongoClient(self._config.DBPATH)
                dbnames = db.database_names()
                if self._dbname in dbnames:
                    print "DB %s already exist in %s" % (self._dbname, self._config.DBPATH)
                    answer = raw_input("Override existing db? [Y/n]")
                    if answer.lower() == "y":
                        for collection in db[self._dbname].collection_names():
                            if collection != "system.indexes":
                                db[self._dbname].drop_collection(collection)
                    else:
                        db.close()
                        sys.exit(0)
                return db
            else:
                return None
        except ConnectionFailure:
            print "Cannot connect to mongodb at %s." % self._config.DBPATH
            sys.exit(1)

    def get_pslist(self):
        data = [p for p in filescan.PSScan(self._config).calculate()]
        pslist = []
        for process in data:
            ps = {}
            # pprint.pprint(vars(process))
            ps['offset'] = int(process.obj_offset)
            ps['name'] = str(process.ImageFileName)
            ps['pid'] = int(process.UniqueProcessId)
            ps['ppid'] = int(process.InheritedFromUniqueProcessId)
            ps['sessionid'] = int(process.Session)
            ps['createtime'] = str(process.CreateTime)
            pslist.append(ps)
        return pslist

    def get_threadlist(self):
        data = [t for t in modscan.ThrdScan(self._config).calculate()] 
        threads = []
        for thread in data:
            # pprint.pprint(vars(thread))
            thrd = {}
            thrd['pid'] = int(thread.Cid.UniqueProcess)
            thrd['tid'] = int(thread.Cid.UniqueThread)
            thrd['offset'] = int(thread.obj_offset)
            thrd['startaddress'] = str(thread.StartAddress)
            thrd['createtime'] = str(thread.CreateTime) or ''
            thrd['exittime'] = str(thread.ExitTime) or ''
            threads.append(thrd)
        return threads

    def get_modulelist(self):
        data = [m for m in modscan.ModScan(self._config).calculate()]
        modules = []
        for module in data:
            # pprint.pprint(vars(module))
            mod = {}
            mod['fulldllname'] = str(module.FullDllName)
            mod['sizeofimage'] = int(module.SizeOfImage)
            mod['checksum'] = str(module.CheckSum)
            modules.append(mod)
        return modules

    def get_netlist(self):
        data = [n for n in sockscan.SockScan(self._config).calculate()]
        socks = []
        for sock in data:
            # pprint.pprint(vars(sock))
            net = {}
            net['offset'] = int(sock.obj_offset)
            net['pid'] = int(sock.Pid)
            net['localport'] = int(sock.LocalPort)
            net['protocol'] = str(protos.protos.get(sock.Protocol.v(), '-'))
            net['localip'] = str(sock.LocalIpAddress)
            net['createtime'] = str(sock.CreateTime)
            socks.append(net)
        return socks

    def get_svclist(self):
        data = [s for s in svcscan.SvcScan(self._config).calculate()]
        services = []
        for service in data:
            # pprint.pprint(service.members.keys())
            svc = {}
            svc['name'] = str(service.ServiceName)
            svc['type'] = str(service.Type)
            svc['serviceprocess'] = str(service.ServiceProcess)
            svc['start'] = str(service.Start)
            svc['state'] = str(service.State)
            svc['drivername'] = str(service.DriverName)
            svc['displayname'] = str(service.DisplayName)
            services.append(svc)
        return services

    def get_registrylist(self):
        data = [r for r in hivelist.HiveList(self._config).calculate()]
        hives = []
        hive_offsets = []
        for registry in data:
            # pprint.pprint(vars(registry))
            if registry.Hive.Signature == 0xbee0bee0 and registry.obj_offset not in hive_offsets:
                try:
                    name = str(registry.FileFullPath or '') or str(registry.FileUserName or '') or str(registry.HiveRootPath or '') or "[no name]"
                except AttributeError:
                    name = "[no name]"
            hive = {}
            hive['name'] = name
            hive['offset'] = int(registry.obj_offset)
            hives.append(hive)
            hive_offsets.append(registry.obj_offset)
        return hives

    def get_evtlogs(self):
        data = [e for e in evtlogs.EvtLogs(self._config).calculate()]
        events = []
        for event in data:
            # pprint.pprint(event)
            evt = {}
            events.append(evt)
        return events

    def get_dlllist(self):
        data = []
        pass

    def createDB(self):
        if self._config.ENABLEDB:
            self._db[self._dbname]['processes'].insert(self._processes)
            self._db[self._dbname]['threads'].insert(self._threads)
            self._db[self._dbname]['modules'].insert(self._modules)
            self._db[self._dbname]['sockets'].insert(self._sockets)
            self._db[self._dbname]['services'].insert(self._services)
            self._db[self._dbname]['hives'].insert(self._hives)
            print "Finish processing, db %s created" % self._dbname

def main():
    info = VolInfo(config=conf.ConfObject()) 
    print("Processing target image with volatility plugins finished.")

if __name__ == "__main__":
    main()
