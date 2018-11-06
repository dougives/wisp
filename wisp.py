import shutil
import os
import json
from subprocess import call, run, check_output, DEVNULL
import re

import subprocess

basepath = os.path.dirname(os.path.realpath(__file__))   
def _find_tools():
    sys_tools = [
        'iw',
        'ip',
        'rfkill',
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
            injector=config['injector'],
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
        assert os.path.isdir(path)
        index = int(next(node 
            for node in os.listdir(path) 
            if node.startswith('rfkill'))[len('rfkill'):])
        assert index
        if Wisp._call_tool('rfkill', 'list', index):
            assert not Wisp._call_tool('rfkill', 'unblock', index)

    @staticmethod
    def _set_link(dev, state):
        assert not Wisp._call_tool(
            'ip', 'link', 'set', 'dev', dev, state)

    class Monitor:
        @staticmethod
        def _get_phy(dev):
            output = None
            with open(f'/sys/class/net/{dev}/phy80211/name', 'r') \
                as file:
                output = file.read()
            assert output
            return output.strip()
        @staticmethod
        def _create_mon_name(dev):
            return f'{dev[:9]}mon'
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
        def _set_channel(self, channel, mon=None):
            assert not Wisp._call_tool('iw',
                'dev', mon if mon else self.mon,
                'set', 'freq', self.channel_map[channel])
        # def _set_unregulated(self, domain='BO'):
        #     assert not Wisp._call_tool('iw',
        #         'dev', self.dev,
        #         'set', 'freq', self.channel_map[channel])
        def start(self):
            if self.mon:
                self._check_mon_type()
                return
            self.mon = self._create_mon_name(self.dev)
            assert not Wisp._call_tool('iw', 
                'phy', self.phy, 
                'interface', 'add', self.mon,
                'type', 'monitor')
            assert not Wisp._call_tool('iw', 
                'dev', self.dev, 'del')
            Wisp._set_link(self.mon, 'up')
            self._set_channel(self.channel)
        def stop(self):
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

    def __init__(self, injector, monitors, delay=4000, jitter=1500):
        self.check_permissions()
        #self.tools : dict = self.find_tools()
        assert tools
        self.injector = injector
        assert self.injector
        self.monitors = dict([ (m.dev, m) for m in monitors ])
        assert self.monitors
        self.delay = delay
        self.jitter = jitter

    def run(self):
        dev = list(self.monitors.keys())[0]
        self._handle_rfkill(dev)
        self._set_link(dev, 'down')
        service_cmd = shutil.which('service')
        if service_cmd:
            for service in self.interfering_services:
                run([ service_cmd, service, 'stop' ],
                    shell=False,
                    stdout=DEVNULL,
                    stderr=DEVNULL)
        for process in self.interfering_processes:
            self._silent_call('kill', '-9', process)
        #for dev in list(self.monitors.keys()):
        #    self._call_tool('iw', dev, 'set', 'monitor', 
        pass


def main():
    wisp = Wisp.from_config()
    wisp.run()
    return 0

if __name__ == '__main__':
    exit(main())
