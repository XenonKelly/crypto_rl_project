#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>
#include <fstream>
#include <string>
#include <map>
#include <algorithm>

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/nr-module.h"
#include "ns3/nr-point-to-point-epc-helper.h"
#include "ns3/energy-module.h"
#include "ns3/simple-device-energy-model.h"
#include "ns3/basic-energy-source-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/antenna-module.h"

using namespace ns3;
using namespace ns3::energy;

NS_LOG_COMPONENT_DEFINE("My5gCryptoSim");

struct CryptoProfile {
    std::string name;
    double energyPerByte;   
    double delayPerByte;    
    double securityScore;   
};

const std::map<std::string, CryptoProfile> g_cryptoProfiles = {
    {"NONE", {"None",      0.000e-6, 0.000e-9, 0.00}},
    {"NEA1", {"SNOW 3G",   1.200e-6, 12.0e-9, 0.70}},
    {"NEA2", {"AES-CTR",   1.000e-6,  8.0e-9, 0.80}},
    {"NEA3", {"ZUC",       0.440e-6,  6.0e-9, 0.85}},
    {"NEA7", {"NEA-7",     1.500e-6, 15.0e-9, 0.90}}
};

CryptoProfile g_activeProfile = g_cryptoProfiles.at("NONE");
double g_totalCryptoEnergy = 0.0;
double g_totalCryptoDelay  = 0.0;
double g_cryptoScale       = 1.0;

double g_keyLengthFactor   = 1.0;      
double g_rekeyIntervalSec  = 0.0;      
double g_simTimeGlobal     = 100.0;    
uint32_t g_rekeyCount      = 0;
double g_rekeyCostEnergy   = 0.005;    
double g_rekeyCostDelay    = 0.01;     
double g_finalSecurityScore = 0.0;
double g_initDelayPerPacket = 0.0;     
double g_initEnergyPerPacket = 0.0;    

double g_e2eSum    = 0.0;
double g_e2eSumSq  = 0.0;
double g_e2eMin    = 1e18;
double g_e2eMax    = 0.0;
uint64_t g_e2eCount = 0;

void ResetGlobalStats() {
    g_totalCryptoEnergy = 0.0; g_totalCryptoDelay = 0.0; g_rekeyCount = 0;
    g_e2eSum = g_e2eSumSq = 0.0; g_e2eMin = 1e18; g_e2eMax = 0.0; g_e2eCount = 0;
    g_finalSecurityScore = 0.0;
}

void PerformRekey() {
    if (g_rekeyIntervalSec <= 0) return;
    
    double now = Simulator::Now().GetSeconds();
    if (now + g_rekeyIntervalSec > g_simTimeGlobal) return;
    
    g_totalCryptoEnergy += g_rekeyCostEnergy;
    g_totalCryptoDelay  += g_rekeyCostDelay;
    g_rekeyCount++;
    NS_LOG_INFO("Re-keying event #" << g_rekeyCount << " at " << now << "s");
    
    Simulator::Schedule(Seconds(g_rekeyIntervalSec), &PerformRekey);
}

class AppHeader : public Header {
public:
    AppHeader() : m_timestamp(0) {}
    virtual ~AppHeader() {}
    void SetTimestamp(uint64_t ts) { m_timestamp = ts; }
    uint64_t GetTimestamp() const  { return m_timestamp; }

    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::AppHeader")
            .SetParent<Header>().SetGroupName("Applications").AddConstructor<AppHeader>();
        return tid;
    }
    virtual TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    virtual void Print(std::ostream &os) const override { os << "timestamp=" << m_timestamp; }
    virtual uint32_t GetSerializedSize() const override { return sizeof(uint64_t); }
    virtual void Serialize(Buffer::Iterator start) const override { start.WriteU64(m_timestamp); }
    virtual uint32_t Deserialize(Buffer::Iterator start) override { m_timestamp = start.ReadU64(); return GetSerializedSize(); }
private:
    uint64_t m_timestamp;
};

class CryptoUdpClient : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::CryptoUdpClient")
            .SetParent<Application>().SetGroupName("Applications").AddConstructor<CryptoUdpClient>();
        return tid;
    }
    CryptoUdpClient() : m_socket(nullptr), m_peerPort(0), m_packetSize(1024),
                        m_interval(Seconds(0.1)), m_maxPackets(1000000),
                        m_sent(0), m_running(false) {}
    virtual ~CryptoUdpClient() { m_socket = nullptr; }

    void SetRemote(Address ip, uint16_t port) { m_peerAddress = ip; m_peerPort = port; }
    void SetPacketSize(uint32_t size)         { m_packetSize = size; }
    void SetInterval(Time interval)           { m_interval = interval; }
    void SetMaxPackets(uint32_t count)        { m_maxPackets = count; }

private:
    virtual void StartApplication() override {
        m_running = true; m_sent = 0;
        if (!m_socket) {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_socket->Bind();
            Ipv4Address ipv4 = Ipv4Address::ConvertFrom(m_peerAddress);
            m_socket->Connect(InetSocketAddress(ipv4, m_peerPort));
        }
        ScheduleTx();
    }
    virtual void StopApplication() override {
        m_running = false;
        if (m_sendEvent.IsPending()) Simulator::Cancel(m_sendEvent);
        if (m_cryptoDelayEvent.IsPending()) Simulator::Cancel(m_cryptoDelayEvent);
        if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    }
    void ScheduleTx() {
        if (m_running) m_sendEvent = Simulator::Schedule(m_interval, &CryptoUdpClient::Send, this);
    }
    void Send() {
        if (!m_running || (m_maxPackets > 0 && m_sent >= m_maxPackets)) { StopApplication(); return; }
        m_currentPacketTimestamp = Simulator::Now().GetNanoSeconds();

        double cryptoDelaySec = g_initDelayPerPacket + 
                                m_packetSize * g_activeProfile.delayPerByte * g_cryptoScale * g_keyLengthFactor;
        double cryptoEnergyJ  = g_initEnergyPerPacket + 
                                m_packetSize * g_activeProfile.energyPerByte * g_cryptoScale * g_keyLengthFactor;

        g_totalCryptoDelay += cryptoDelaySec;
        g_totalCryptoEnergy += cryptoEnergyJ;

        m_cryptoDelayEvent = Simulator::Schedule(Seconds(cryptoDelaySec), &CryptoUdpClient::DoSend, this);
        ScheduleTx();
    }
    void DoSend() {
        Ptr<Packet> p = Create<Packet>(m_packetSize);
        AppHeader hdr; hdr.SetTimestamp(m_currentPacketTimestamp);
        p->AddHeader(hdr);
        m_socket->Send(p); m_sent++;
    }
    Ptr<Socket> m_socket;
    Address m_peerAddress;
    uint16_t m_peerPort;
    uint32_t m_packetSize;
    Time m_interval;
    uint32_t m_maxPackets;
    uint32_t m_sent;
    EventId m_sendEvent;
    EventId m_cryptoDelayEvent;
    uint64_t m_currentPacketTimestamp;
    bool m_running;
};

class CryptoUdpServer : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::CryptoUdpServer")
            .SetParent<Application>().SetGroupName("Applications").AddConstructor<CryptoUdpServer>();
        return tid;
    }
    CryptoUdpServer() : m_port(1234), m_socket(nullptr) {}
    virtual ~CryptoUdpServer() { m_socket = nullptr; }
    void SetPort(uint16_t port) { m_port = port; }
private:
    virtual void StartApplication() override {
        if (!m_socket) {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
            m_socket->SetRecvCallback(MakeCallback(&CryptoUdpServer::HandleRead, this));
        }
    }
    virtual void StopApplication() override { if (m_socket) { m_socket->Close(); m_socket = nullptr; } }
    void HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet; Address from;
        while ((packet = socket->RecvFrom(from))) {
            AppHeader hdr; packet->RemoveHeader(hdr);
            uint64_t nowNs = Simulator::Now().GetNanoSeconds();
            double delaySec = (nowNs - hdr.GetTimestamp()) * 1e-9;
            g_e2eSum += delaySec; g_e2eSumSq += delaySec * delaySec;
            if (delaySec < g_e2eMin) g_e2eMin = delaySec;
            if (delaySec > g_e2eMax) g_e2eMax = delaySec;
            g_e2eCount++;
        }
    }
    uint16_t m_port; Ptr<Socket> m_socket;
};

int main(int argc, char* argv[])
{
    double simTime = 100.0;
    double udpInterval = 0.01;
    uint32_t packetSize = 4096;
    std::string cryptoAlg = "NEA3";
    std::string outputCsv = "crypto_rl_dataset.csv";
    uint32_t keyLength = 128;
    double rekeyIntervalSec = 10.0;

    CommandLine cmd;
    cmd.AddValue("simTime", "Simulation time (s)", simTime);
    cmd.AddValue("udpInterval", "UDP interval (s)", udpInterval);
    cmd.AddValue("packetSize", "UDP packet size (bytes)", packetSize);
    cmd.AddValue("cryptoAlg", "Crypto: NEA1, NEA2, NEA3, NEA7, NONE", cryptoAlg);
    cmd.AddValue("outputCsv", "Output CSV filename", outputCsv);
    cmd.AddValue("cryptoScale", "Multiplier for crypto delay/energy (for RL)", g_cryptoScale);
    cmd.AddValue("keyLength", "Key length in bits (128 or 256)", keyLength);
    cmd.AddValue("rekeyInterval", "Re-keying interval in seconds (0=disabled)", rekeyIntervalSec);
    cmd.AddValue("rekeyCostEnergy", "Energy cost per re-key event (J)", g_rekeyCostEnergy);
    cmd.AddValue("rekeyCostDelay", "Delay cost per re-key event (s)", g_rekeyCostDelay);
    cmd.AddValue("initDelay", "Fixed init delay per packet (s, default 0)", g_initDelayPerPacket);
    cmd.AddValue("initEnergy", "Fixed init energy per packet (J, default 0)", g_initEnergyPerPacket);
    cmd.Parse(argc, argv);

    g_simTimeGlobal = simTime;
    ResetGlobalStats();
    g_activeProfile = g_cryptoProfiles.at(cryptoAlg);
    
    g_keyLengthFactor = (keyLength == 256 && cryptoAlg == "NEA2") ? 1.35 : 1.0;
    g_rekeyIntervalSec = rekeyIntervalSec;

    LogComponentEnable("My5gCryptoSim", LOG_LEVEL_INFO);
    NS_LOG_INFO("Crypto: " << g_activeProfile.name << " | Key: " << keyLength << "b (factor=" << g_keyLengthFactor << ") | Rekey: " << rekeyIntervalSec << "s");

    NodeContainer gnbNodes; gnbNodes.Create(1);
    NodeContainer ueNodes;  ueNodes.Create(1);
    NodeContainer remoteHostContainer; remoteHostContainer.Create(1);

    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(gnbNodes); mobility.Install(ueNodes);
    gnbNodes.Get(0)->GetObject<ConstantPositionMobilityModel>()->SetPosition(Vector(0.0, 0.0, 10.0));
    ueNodes.Get(0)->GetObject<ConstantPositionMobilityModel>()->SetPosition(Vector(20.0, 0.0, 1.5));

    Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();
    nrHelper->SetBeamformingHelper(idealBeamformingHelper); nrHelper->SetEpcHelper(epcHelper);

    CcBwpCreator ccBwpCreator;
    CcBwpCreator::SimpleOperationBandConf bandConf(28e9, 100e6, 1, BandwidthPartInfo::UMi_StreetCanyon);
    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);
    nrHelper->InitializeOperationBand(&band);
    BandwidthPartInfoPtrVector allBwps = CcBwpCreator::GetAllBwps({band});

    idealBeamformingHelper->SetAttribute("BeamformingMethod", TypeIdValue(DirectPathBeamforming::GetTypeId()));
    epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));

    NetDeviceContainer gnbDevs = nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    NetDeviceContainer ueDevs  = nrHelper->InstallUeDevice(ueNodes, allBwps);

    nrHelper->GetGnbPhy(gnbDevs.Get(0), 0)->SetAttribute("Numerology", UintegerValue(2));
    nrHelper->GetGnbPhy(gnbDevs.Get(0), 0)->SetAttribute("TxPower", DoubleValue(35.0));

    for (auto it = gnbDevs.Begin(); it != gnbDevs.End(); ++it) DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for (auto it = ueDevs.Begin(); it != ueDevs.End(); ++it)   DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();

    InternetStackHelper internet; internet.Install(ueNodes); internet.Install(remoteHostContainer);
    Ipv4InterfaceContainer ueIpIface = epcHelper->AssignUeIpv4Address(ueDevs);
    for (uint32_t i = 0; i < ueNodes.GetN(); ++i) {
        Ptr<Ipv4StaticRouting> ueStaticRouting = Ipv4RoutingHelper::GetRouting<Ipv4StaticRouting>(ueNodes.Get(i)->GetObject<Ipv4>()->GetRoutingProtocol());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    Ptr<Node> pgw = epcHelper->GetPgwNode();
    PointToPointHelper p2ph; p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gbps"))); p2ph.SetChannelAttribute("Delay", TimeValue(MilliSeconds(10)));
    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHostContainer.Get(0));
    Ipv4AddressHelper ipv4h; ipv4h.SetBase("1.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting = ipv4RoutingHelper.GetStaticRouting(remoteHostContainer.Get(0)->GetObject<Ipv4>());
    remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    nrHelper->AttachToClosestEnb(ueDevs, gnbDevs); nrHelper->EnableTraces();

    BasicEnergySourceHelper basicSourceHelper;
    basicSourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(20000.0));
    basicSourceHelper.Set("BasicEnergySupplyVoltageV", DoubleValue(3.7));
    EnergySourceContainer sources = basicSourceHelper.Install(ueNodes);
    Ptr<EnergySource> energySource = sources.Get(0);
    Ptr<SimpleDeviceEnergyModel> simpleDeviceEnergyModel = CreateObject<SimpleDeviceEnergyModel>();
    simpleDeviceEnergyModel->SetEnergySource(energySource); energySource->AppendDeviceEnergyModel(simpleDeviceEnergyModel);
    simpleDeviceEnergyModel->SetNode(ueNodes.Get(0)); simpleDeviceEnergyModel->SetCurrentA(0.5);

    uint16_t port = 1234;
    Ptr<CryptoUdpServer> server = CreateObject<CryptoUdpServer>(); server->SetPort(port); remoteHostContainer.Get(0)->AddApplication(server);
    Ptr<CryptoUdpClient> client = CreateObject<CryptoUdpClient>(); client->SetRemote(internetIpIfaces.GetAddress(1), port);
    client->SetInterval(Seconds(udpInterval)); client->SetMaxPackets(1000000); client->SetPacketSize(packetSize);
    ueNodes.Get(0)->AddApplication(client);
    server->SetStartTime(Seconds(0.1)); client->SetStartTime(Seconds(0.2));
    server->SetStopTime(Seconds(simTime)); client->SetStopTime(Seconds(simTime));

    FlowMonitorHelper flowmonHelper; Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

    if (g_rekeyIntervalSec > 0) Simulator::Schedule(Seconds(g_rekeyIntervalSec), &PerformRekey);

    NS_LOG_INFO("Starting simulation for " << simTime << " seconds...");
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    double throughputKbps = 0.0, flowDelayMs = 0.0;
    for (auto &flow : stats) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
        if (t.sourceAddress == ueIpIface.GetAddress(0) && t.destinationAddress == internetIpIfaces.GetAddress(1)) {
            if (flow.second.rxPackets > 0) {
                flowDelayMs = flow.second.delaySum.GetSeconds() / flow.second.rxPackets * 1000.0;
                throughputKbps = flow.second.rxBytes * 8.0 / (simTime * 1000.0);
            }
        }
    }

    energySource->UpdateEnergySource();
    double baseEnergy = 20000.0 - energySource->GetRemainingEnergy();
    double totalEnergy = baseEnergy + g_totalCryptoEnergy;
    
    double batteryPercent = std::max(0.0, ((20000.0 - totalEnergy) / 20000.0) * 100.0);

    double meanE2E = 0.0, minE2E = 0.0, maxE2E = 0.0, stddevE2E = 0.0;
    if (g_e2eCount > 0) {
        meanE2E = g_e2eSum / g_e2eCount; minE2E = g_e2eMin; maxE2E = g_e2eMax;
        double variance = (g_e2eSumSq / g_e2eCount) - (meanE2E * meanE2E);
        stddevE2E = std::sqrt(std::max(0.0, variance));
    }

    double baseSec = g_activeProfile.securityScore;
    double lenBonus = (keyLength == 256) ? 0.10 : 0.0;
    const double REKEY_BONUS_K = 2.0;
    const double REKEY_BONUS_MAX = 0.2;
    double freqBonus = (rekeyIntervalSec > 0) ? std::min(REKEY_BONUS_MAX, REKEY_BONUS_K / rekeyIntervalSec) : 0.0;
    g_finalSecurityScore = std::min(1.0, baseSec + lenBonus + freqBonus);

    std::cout << std::fixed << std::setprecision(4);
    NS_LOG_INFO("\n=== SIMULATION RESULTS ===");
    NS_LOG_INFO("Algorithm          : " << g_activeProfile.name);
    NS_LOG_INFO("Key Length         : " << keyLength << " bits (factor=" << g_keyLengthFactor << ")");
    NS_LOG_INFO("Rekey Interval     : " << rekeyIntervalSec << " s (events: " << g_rekeyCount << ")");
    NS_LOG_INFO("Security Score     : " << g_finalSecurityScore);
    NS_LOG_INFO("Throughput         : " << throughputKbps << " Kbps");
    NS_LOG_INFO("FlowMonitor Delay  : " << flowDelayMs << " ms");
    NS_LOG_INFO("E2E Delay (mean)   : " << meanE2E * 1000.0 << " ms");
    NS_LOG_INFO("E2E Delay (stddev) : " << stddevE2E * 1000.0 << " ms");
    NS_LOG_INFO("Crypto Energy      : " << g_totalCryptoEnergy << " J");
    NS_LOG_INFO("Total Energy       : " << totalEnergy << " J");
    NS_LOG_INFO("Final Battery      : " << batteryPercent << " %");
    NS_LOG_INFO("==========================\n");

    bool writeHeader = true;
    std::ifstream testFile(outputCsv); if (testFile.good()) writeHeader = false; testFile.close();
    std::ofstream csvFile(outputCsv, std::ios_base::app);
    if (writeHeader) csvFile << "Algorithm,KeyLength,RekeyInterval,RekeyCount,SecurityScore,ThroughputKbps,FlowDelayMs,E2EMeanDelayMs,E2EStdDevDelayMs,CryptoEnergyJ,TotalEnergyJ,BatteryPercent\n";
    
    csvFile << g_activeProfile.name << "," << keyLength << "," << rekeyIntervalSec << "," << g_rekeyCount << ","
            << g_finalSecurityScore << "," << throughputKbps << "," << flowDelayMs << ","
            << meanE2E * 1000.0 << "," << stddevE2E * 1000.0 << ","
            << g_totalCryptoEnergy << "," << totalEnergy << "," << batteryPercent << "\n";
    csvFile.close();
    std::cout << "Results appended to " << outputCsv << std::endl;

    Simulator::Destroy();
    return 0;
}