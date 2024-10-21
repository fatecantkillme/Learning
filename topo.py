from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink


class MyTopo(Topo):

    def __init__(self):
        Topo.__init__(self)
        #add host and switch
        Host1 = self.addHost('h1') 
        Host2 = self.addHost('h2')
        Host3 = self.addHost('h3')
        Host4 = self.addHost('h4')
        Switch1= self.addSwitch('s1')
        Switch2= self.addSwitch('s2')
        #add link
        self.addLink(Host1, Switch1)
        self.addLink(Host2, Switch2)
        self.addLink(Host3, Switch2)
        self.addLink(Host4, Switch2)
        self.addLink(Switch1,Switch2,bw=10,delay='10ms')
    
def run():
        setLogLevel('info')
        topo= MyTopo()
        net=Mininet(topo=topo, link=TCLink)
        net.start()
        
        CLI(net)
        net.stop()


if __name__ == '__main__':
    run()
