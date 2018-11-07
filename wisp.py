import shutil
import os
import json
from subprocess import call, run, check_output, Popen, DEVNULL, PIPE
import re
from multiprocessing import Process
from time import time
from signal import signal, SIGKILL, SIGABRT, SIGINT
import sys

basepath = os.path.dirname(os.path.realpath(__file__))   
def _find_tools():
    sys_tools = [
        'iw',
        'ip',
        'rfkill',
        'aireplay-ng',
    ]
    project_tools = [
        'dream'
    ]
    tools = {
        **dict([ (t, shutil.which(t)) 
            for t in sys_tools ]),
        **dict([ (t, os.path.join(basepath, t)) 
            for t in project_tools ]),
    }
    for path in tools.values():
        assert os.path.isfile(path)
    return tools
tools : dict = _find_tools()

class Wisp:
    @staticmethod
    def from_config(path=None):
        name = 'wisp.json'
        defaults = (
            os.path.join(basepath, name),
            os.path.join('/etc', name),
        )
        path = path or next(p 
            for p in defaults 
            if os.path.isfile(p))
        assert path
        config = None
        with open(path, 'r') as file:
            config = json.load(file)
        assert config
        return Wisp(
            injector=Wisp.Monitor(config['injector'], 1),
            monitors=[ Wisp.Monitor(dev, **config['monitors'][dev])
                for dev in config['monitors'].keys() ],
            delay=config['timing']['delay'],
            jitter=config['timing']['jitter'])

    @staticmethod
    def check_permissions():
        assert not os.geteuid()
        pass

    @staticmethod
    def _silent_call(name, *args):
        return call(
            [ name ] + [ str(arg) for arg in args],
            shell=False,
            stdout=DEVNULL,
            stderr=DEVNULL)

    @staticmethod
    def _call_tool(name, *args):
        assert name in tools.keys()
        return Wisp._silent_call(tools[name], *args)

    @staticmethod
    def _handle_rfkill(dev):
        assert dev
        path = f'/sys/class/net/{dev}/phy80211/'
        if not os.path.isdir(path):
            return
        index = int(next(node 
            for node in os.listdir(path) 
            if node.startswith('rfkill'))[len('rfkill'):])
        if Wisp._call_tool('rfkill', 'list', index):
            assert not Wisp._call_tool('rfkill', 'unblock', index)

    @staticmethod
    def _set_link(dev, state):
        e = Wisp._call_tool(
            'ip', 'link', 'set', 'dev', dev, state)
        print(dev, state, e)
        assert not e
        return

    class Monitor:
        @staticmethod
        def _get_phy(dev):
            output = None
            with open(f'/sys/class/net/{dev}/phy80211/name', 'r') \
                as file:
                output = file.read()
            assert output
            return output.strip()
        def _create_mon_name(self):
            return f'{self.phy}wisp'
        def _check_mon_type(self):
            typepath = \
                f'/sys/class/ieee80211/{self.phy}' \
                + f'/device/net/{self.mon}/type'
            assert os.path.isfile(typepath)
            with open(typepath, 'r') as file:
                linktype = int(file.read())
                assert linktype == 803
            return
        _channel_re : re.Pattern = re.compile(
            r'^\s*\*\s+(\d+)\s+MHz\s+\[(\d+)\]\s+.*$')
        def set_channel(self, channel, mon=None):
            assert not Wisp._call_tool('iw',
                'dev', mon if mon else self.mon,
                'set', 'freq', self.channel_map[channel])
        # def _set_unregulated(self, domain='BO'):
        #     assert not Wisp._call_tool('iw',
        #         'dev', self.dev,
        #         'set', 'freq', self.channel_map[channel])
        def _dream_process(self, queue, assoc=False, dump=True):
            dream_re = re.compile(
                r'^([0-9A-Fa-f]{12}),([0-9A-Fa-f]{12}),$')
            cmd = [ tools['dream'] ] \
                + ([ '--a' ] if assoc else []) \
                + ([ '--d', f'{self.phy}-{int(time())}.cap' ] \
                    if dump else []) \
                + ([ '-bs' ]) \
                + ([ self.mon ])
            print(cmd)
            dream = Popen(cmd, 
                stdin=DEVNULL,
                stdout=PIPE,
                stderr=DEVNULL,
                cwd=basepath,
                text=True)
            assert dream
            def read():
                line = dream.stdout.readline().strip()
                while line:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    line = dream.stdout.readline()
            read()
        def start(self):
            if self.mon:
                self._check_mon_type()
                return
            Wisp._set_link(self.dev, 'down')
            self.mon = self._create_mon_name()
            assert not Wisp._call_tool('iw', 
                'phy', self.phy, 
                'interface', 'add', self.mon,
                'type', 'monitor')
            assert not Wisp._call_tool('iw', 
                'dev', self.dev, 'del')
            Wisp._set_link(self.mon, 'up')
        def listen(self):
            assert self.mon
            self.set_channel(self.channel)
            self.dream = Process(
                target=self._dream_process, 
                args=(None,))
            self.dream.start()
        def stop(self):
            if self.dream:
                self.dream.terminate()
                while self.dream.is_alive():
                    pass
            self.dream.close()
            self.dream = None
            assert self.mon
            self._check_mon_type()
            assert not Wisp._call_tool('iw', 
                'dev', self.mon, 'del')
            self.mon = None
            assert not Wisp._call_tool('iw', 
                'phy', self.phy, 
                'interface', 'add', self.dev,
                'type', 'managed')

        def __init__(self, dev, channel):
            assert os.path.isdir(f'/sys/class/net/{dev}/phy80211')
            self.dev = dev
            self.channel = channel
            self.phy = self._get_phy(dev)
            self.info = check_output([ 'iw', 
                'phy', self.phy, 'info' ]).decode()
            self.channel_map = dict(
                (int(chan), int(freq))
                for chan, freq in [ 
                    match.groups()[::-1]
                    for match in [ 
                        self._channel_re.match(line) 
                        for line in self.info.splitlines() ] 
                    if match ])
            self.mon = None
            self.dream = None

        def __eq__(self, other):
            if isinstance(other, Monitor):
                eq = self.phy == other.phy
                if eq:
                    assert self.dev == other.dev
                    assert self.channel == other.channel
                    assert self.mon == other.mon
            return NotImplemented
        def __hash__(self):
            return int.from_bytes(self.phy.encode(), 'little')

    interfering_processes = [
        'wpa_action', 
        'wpa_supplicant', 
        'wpa_cli', 
        'dhclient', 
        'ifplugd', 
        'dhcdbd', 
        'dhcpcd', 
        'udhcpc', 
        'NetworkManager', 
        'knetworkmanager', 
        'avahi-autoipd', 
        'avahi-daemon', 
        'wlassistant', 
        'wifibox',
    ]
    interfering_services = [
        'network-manager',
        'NetworkManager',
        'avahi-daemon',
    ]

    DEAUTH_REQ = \
        '\xC0\x00\x3A\x01' \
        '\xCC\xCC\xCC\xCC\xCC\xCC' \
        '\xBB\xBB\xBB\xBB\xBB\xBB' \
        '\xBB\xBB\xBB\xBB\xBB\xBB' \
        '\x00\x00\x07\x00'

    def _deauth(self, channel, bss, sta=None, count=4): 
        assert 0
        assert self.injector.mon
        self.injector.set_channel(channel)
        def sep_mac(mac):
            assert isinstance(mac, bytes)
            assert len(mac) == 6
            return ':'.join(f'{c:02x}' for c in mac)
        aireplay = Popen([ tools['aireplay-ng'], '-0' ]
            + [ count ]
            + [ '-a', sep_mac(bss) ]
            + [ '-c', sep_mac(sta) ] if sta else []
            + [ self.injector.mon ],
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=DEVNULL,
            cwd=basepath,
            text=True)
        assert aireplay

        line = aireplay.stdout.readline().strip()
        while line:
            print(line)
            line = aireplay.stdout.readline()

    def _run_process(self):
        self.dream = Process(target=self._dream_process)
        self.dream.start()
        pass

    def run(self):
        dev = list(self.monitors.keys())[0]
        self._handle_rfkill(dev)
        service_cmd = shutil.which('service')
        if service_cmd:
            for service in self.interfering_services:
                run([ service_cmd, service, 'stop' ],
                    shell=False,
                    stdout=DEVNULL,
                    stderr=DEVNULL)
        for process in self.interfering_processes:
            self._silent_call('kill', '-9', process)
        mon = self.monitors['wlx9cefd5fd276a']
        mon.start()
        mon.listen()
        # assert 0
        # for mon in self.monitors:
        #     mon.start()
        #     mon.dream()
        # self.injector.start()

        pass

    def __init__(self, injector, monitors, delay=4000, jitter=1500):
        self.check_permissions()
        #self.tools : dict = self.find_tools()
        assert tools
        self.monitors = dict([ (m.dev, m) for m in monitors ])
        assert self.monitors
        for mon in self.monitors.values():
            assert not mon.mon
        self.injector = injector
        assert self.injector
        assert self.injector not in self.monitors
        self.delay = delay
        self.jitter = jitter

def main():
    wisp = Wisp.from_config()
    wisp.run()
    return 0

if __name__ == '__main__':
    exit(main())
