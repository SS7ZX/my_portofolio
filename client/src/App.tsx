import { useEffect, useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence, useScroll, useTransform, useSpring, useMotionValue } from 'framer-motion';
import { 
  Shield, Terminal, Award, Users, Trophy,
  Database, Code2, X, Activity, Globe, Wifi, AlertTriangle, Zap, ExternalLink,
  Lock, Search, Fingerprint, Server,
  Radar,
  Gauge, Rocket,
  Loader, RefreshCw, Check
} from 'lucide-react';

// ==================== COMPREHENSIVE TYPE DEFINITIONS ====================
interface Project {
  _id: string;
  title: string;
  description: string;
  tech: string[];
  link?: string;
  securityLevel: 'Kernel' | 'High' | 'Standard';
  audit: {
    encryption: string;
    compliance: string;
    threats: string;
  };
  caseStudy?: {
    challenge: string;
    solution: string;
    result: string;
  };
  category?: string;
  stars?: number;
  downloads?: number;
}

interface Experience {
  _id: string;
  title: string;
  organization: string;
  description: string;
  period?: string;
  achievements?: string[];
}

interface SystemMetrics {
  cpu: number;
  ram: number;
  disk: number;
  network: number;
  processes: number;
  uptime: string;
}

interface ThreatAlert {
  id: number;
  time: string;
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  msg: string;
  source: string;
  blocked: boolean;
}

// ==================== COMPREHENSIVE DATA ====================
const STATIC_EXPERIENCES: Experience[] = [
  {
    _id: "e1",
    title: "Vice President (Wakil Himpunan)",
    organization: "Universitas Siber Indonesia, IS&T Student Association",
    description: "Leading strategic initiatives and coordinating departmental synergy for 3rd-semester Information Systems students.",
    period: "2024 - Present",
    achievements: ["Led 200+ member organization", "Organized 10+ technical events", "Increased engagement by 150%"]
  },
  {
    _id: "e2",
    title: "Head of Basketball Division",
    organization: "Sports UKM (Student Activity Unit)",
    description: "Managing team logistics, training schedules, and competitive strategy for the university basketball division.",
    period: "2023 - Present",
    achievements: ["Managed 30+ athletes", "Won 3 regional championships", "Improved team performance 40%"]
  }
];

const STATIC_PROJECTS: Project[] = [
  {
    _id: "p1",
    title: "💵 C-Pay Ecosystem",
    description: "Independently engineered a closed-loop payment system with secure transaction logic and MERN architecture.",
    tech: ["Node.js", "MongoDB", "Express", "Docker", "Redis", "JWT"],
    link: "https://github.com/SS7ZX/CPAY",
    securityLevel: 'High',
    audit: { encryption: "AES-256-GCM", compliance: "PCI-DSS Ready", threats: "SQLi, XSS, CSRF" },
    category: "FinTech",
    stars: 45,
    downloads: 1200
  },
  {
    _id: "p2",
    title: "📲 LifeFin UMKM Web-App",
    description: "Architected a financial platform for MSMEs with a focus on data encryption and WCAG accessibility.",
    tech: ["React", "Firebase", "Tailwind", "Python", "UI/UX Design", "TypeScript"],
    link: "https://lifefin.web.app/",
    securityLevel: 'Standard',
    audit: { encryption: "SSL/TLS 1.3", compliance: "GDPR", threats: "Broken Auth" },
    category: "Web Development",
    stars: 32,
    downloads: 850
  },
  {
    _id: "p3",
    title: "🌐 VAPT Excellence Audit",
    description: "Officially recognized by Universitas Siber Indonesia for excellence in Security System Evaluation and vulnerability mitigation.",
    tech: ["Burp Suite", "OWASP Top 10", "Network Security", "cURL", "Nmap", "Metasploit"],
    securityLevel: 'High',
    audit: { encryption: "Handshake Analysis", compliance: "OWASP ASVS", threats: "Zero Day Discovery" },
    category: "Security",
    stars: 78,
    downloads: 0
  },
  {
    _id: "p4",
    title: "👾 Bhaswara Regional Learning",
    description: "National Top 50 Finalist. A gamified regional language learning prototype.",
    tech: ["Product Design", "Figma", "Web Dev", "Prototyping", "User Testing", "HTML/CSS", "JavaScript", "Android Studio"],
    link: "",
    securityLevel: 'Standard',
    audit: { encryption: "Bcrypt", compliance: "WCAG 2.1", threats: "Insecure Direct Object Reference" },
    category: "Education",
    stars: 28,
    downloads: 450
  },
  {
    _id: "p5",
    title: "🔎 NEXUS Originality Engine",
    description: "Enterprise SaaS for academic integrity utilizing Google Cloud Search API and JSON-key authentication. Engineered real-time similarity indexing across global web sources with 96% detection accuracy.",
    tech: ["Google Cloud API", "Node.js", "JSON Auth", "Python", "Machine Learning", "NLP"],
    securityLevel: 'High',
    audit: { encryption: "RSA-4096", compliance: "SaaS Integrity", threats: "API Scraping, Key Leakage" },
    category: "AI/ML",
    stars: 92,
    downloads: 2100
  },
  {
    _id: "p6",
    title: "🛡️ Aegis Fortress: eBPF Kernel EDR",
    description: "A high-performance Linux EDR built with C (eBPF) and Python. Intercepts syscalls at the kernel level to detect and neutralize threats (SIGKILL) with near-zero latency.",
    tech: ["C (eBPF)", "Linux Kernel", "BCC", "Python", "Security Engineering", "System Programming"],
    link: "https://github.com/SS7ZX/Aegis-Fortress-EDR",
    securityLevel: 'Kernel',
    audit: { encryption: "Kernel-Space Memory Protection", compliance: "NIST 800-53", threats: "Rootkits, Syscall Hijacking" },
    category: "Kernel Security",
    stars: 156,
    downloads: 3400
  },
  {
    _id: "p7",
    title: "🛡️ Project Lyncis: LSM-Powered EDR",
    description: "A kernel-native EDR utilizing eBPF and Linux Security Modules (LSM) to prevent memory-based exploits. Implements synchronous syscall vetoing (-EPERM) and automated memory carving (gcore) for instant forensic triage.",
    tech: ["C", "eBPF", "LSM Hooks", "Python", "Linux Forensics", "Memory Analysis"],
    link: "https://github.com/SS7ZX/Lyncis-EDR",
    securityLevel: 'Kernel',
    audit: { encryption: "LSM Hook Sandboxing", compliance: "SOC2", threats: "Buffer Overflow, ROP Chains" },
    category: "Kernel Security",
    stars: 134,
    downloads: 2800
  },
  {
    _id: "p8",
    title: "📊 Mercedes-Benz Strategic BMC",
    description: "Business Model Canvas analysis for automotive digital transformation. Focused on AI factory automation and luxury EV market positioning.",
    tech: ["Business Architecture", "Strategy", "Market Analysis", "Data Visualization"],
    link: "https://www.figma.com/design/C4Oq4juiV2VQpPvwUBJJJj/BMC-Mercedez-Benz?node-id=0-1&t=iVrAzuBGBj2xDkzG-1",
    securityLevel: 'Standard',
    audit: { encryption: "Access Control Lists", compliance: "Strategic ISO", threats: "Data Exfiltration" },
    category: "Business Strategy",
    stars: 41,
    downloads: 0
  },
  {
    _id: "p9",
    title: "🌌 Aether-Apex: Kernel Research",
    description: "Advanced LKM research exploring Ring 0 hooks, VFS interception, and EDR evasion via dynamic symbol resolution (Kprobes).",
    tech: ["C", "Linux Kernel", "x86_64 ASM", "Forensics", "Reverse Engineering"],
    link: "https://github.com/SS7ZX/Aether-Apex-Kernel-Research.git",
    securityLevel: 'Kernel',
    audit: {
      encryption: "Kernel Memory Mapping",
      compliance: "PoC Research Only",
      threats: "SCT Divergence, Kprobe Latency"
    },
    caseStudy: {
      challenge: "Bypassing kallsyms_lookup_name restrictions in Linux Kernel 5.7+.",
      solution: "Implemented Kprobe-based offset calculation to dynamically resolve unexported symbols.",
      result: "Successfully demonstrated VFS-layer stealth with forensic detection countermeasures."
    },
    category: "Research",
    stars: 189,
    downloads: 4200
  },
{
  _id: "p10",
  title: "❄️ FreezyLe: Serverless FinTech MVP",
  description: "A serverless FinTech MVP for digital asset top-ups. Originally architected on MERN, then re-engineered to a Serverless Firebase infrastructure to achieve sub-millisecond data synchronization and edge-network hosting.",
  tech: ["React.js", "Firebase Auth", "Cloud Firestore", "Serverless Functions", "Tailwind"],
  link: "https://freezylestore.web.app/",
  securityLevel: "High",
  category: "Cloud Architecture",
  stars: 84,
  downloads: 1200,
  audit: {
    encryption: "Google Cloud KMS / SSL",
    compliance: "OAuth 2.0 Standard",
    threats: "Prevents Client-Side Injection via Firestore Rules"
  },
  caseStudy: {
    challenge: "The initial MongoDB architecture introduced latency in transaction status updates for users.",
    solution: "Migrated the database layer to Cloud Firestore, utilizing 'onSnapshot' listeners for real-time payment status reflection.",
    result: "Reduced transaction UI latency by 90% and eliminated 100% of server maintenance costs."
  }
},
{ 
  _id: "p11",
  title: "🏛️ Tartarus EDR: Omniscient Kernel Shield",
  description: "A proactive, kernel-native Endpoint Detection and Response system leveraging eBPF to monitor, intercept, and neutralize unauthorized file access at the system-call level. Bridges Ring 0 kernel space to a Rust/Discord cloud relay with zero-leak security policy enforcement.",
  tech: ["C (eBPF)", "Rust", "Linux Kernel", "BPF Ring Buffer", "Discord API", "Tokio Runtime", "SIGKILL Enforcement"],
  link: "https://github.com/SS7ZX/Tartatus-EDR.git",
  securityLevel: 'Kernel',

  audit: {
    encryption: "Kernel-Space Memory Protection + BPF Ring Buffer Zero-Copy",
    compliance: "NIST 800-53 / Multi-Vector Defense",
    threats: "Rootkits, Syscall Hijacking, /etc/shadow, SSH Key Exfiltration, Sudoers Tampering"
  },
  category: "Kernel Security",
  stars: 2,
  downloads: 1,
  caseStudy: {
    challenge: "Achieving zero file-descriptor leakage on unauthorized openat() syscalls while preventing recursive kernel panics from the EDR agent intercepting its own network calls to Discord.",
    solution: "Deployed a 3-layer Golden Path architecture: (1) eBPF C Infiltrator hooking openat at Ring 0 with in-line evaluation, (2) bpf_send_signal(9) enforcer killing threads before FD return, (3) Rust control plane with PID Exclusion Logic and tokio::spawn for non-blocking Discord uplink, plus BPF Ring Buffer for zero-copy telemetry streaming.",
    result: "Achieved zero-leak security policy across the full authentication stack (/etc/shadow, SSH keys, sudoers). Structured threat alerts delivered as Discord Rich Embed JSON with stateful forum thread management, bypassing 400 Bad Request errors via mandatory thread_name logic."
  },
},
  {
  _id: "p12",
  title: "🐕‍🦺 Cerberus Auth: Triple-Headed Protocol Sentinel",
  description: "A hardened, multi-stage authentication gateway utilizing XDP (Express Data Path) and hardware-backed mTLS to enforce zero-trust access at the network ingress. Intercepts untrusted packets at the NIC driver level before they reach the TCP stack, preventing pre-auth RCE and DDoS vector exploitation.",
  tech: ["C (XDP/eBPF)", "Rust (Tokio)", "WebAuthn/FIDO2", "mTLS 1.3", "Hardware Security Modules (HSM)", "AES-256-GCM", "QUIC Protocol"],
  link: "https://github.com/SS7ZX/Cerberus-EDR.git",
  securityLevel: "Kernel",
  audit: {
    encryption: "HSM-Backed Private Key Isolation + Chacha20-Poly1305 Wire Encryption",
    compliance: "FIPS 140-3 / Zero-Trust Architecture (ZTA)",
    threats: "Pre-Auth RCE, Syn-Flooding, Man-in-the-Middle (MitM), Replay Attacks, Session Hijacking"
  },
  category: "Network Infrastructure",
  stars: 1,
  downloads: 2,
  caseStudy: {
    challenge: "Enforcing multi-factor authentication and cryptographically verified identity at the packet level without introducing millisecond-scale latency or exposing the internal network stack to unauthenticated handshake vulnerabilities.",
    solution: "Engineered a 'Triple-Head' defense architecture: (1) XDP-based Packet Filter acting as the first head, dropping non-mTLS signed packets at the NIC; (2) Rust-based Identity Orchestrator using WebAuthn for biometric-backed session keys; (3) Dynamic firewall state-machine that only 'unlocks' the kernel TCP stack for validated PIDs, effectively making the server invisible to unauthorized scans.",
    result: "Reduced attack surface by 99.4%; successfully mitigated 10Gbps volumetric DDoS attacks by offloading packet rejection to the XDP driver. Integrated stateful session tracking with sub-millisecond overhead, providing real-time biometric audit logs directly to the Aether-Apex security dashboard."
  }
}
];

// ==================== CINEMATIC BOOT LOADER (KALI-INSPIRED) ====================
const KaliBootLoader = ({ onComplete }: { onComplete: () => void }) => {
  const [stage, setStage] = useState(0);
  const [progress, setProgress] = useState(0);
  const [bootLogs, setBootLogs] = useState<Array<{text: string, type: 'success' | 'info' | 'warning' | 'error'}>>([]);
  const [showDragon, setShowDragon] = useState(true);
  
  const bootSequence = [
    { text: '[ OK ] Starting ADNAN OS Security Framework v4.2.0', type: 'info' as const, duration: 600 },
    { text: '[ OK ] Initializing Kali Linux compatibility layer', type: 'success' as const, duration: 700 },
    { text: '[ OK ] Loading eBPF security hooks...', type: 'success' as const, duration: 800 },
    { text: '[ OK ] Mounting encrypted /root filesystem', type: 'success' as const, duration: 600 },
    { text: '[ OK ] Starting firewall: nftables [ENABLED]', type: 'success' as const, duration: 700 },
    { text: '[ OK ] Initializing intrusion detection: Suricata', type: 'success' as const, duration: 900 },
    { text: '[ OK ] Loading kernel security modules: SELinux', type: 'success' as const, duration: 700 },
    { text: '[ OK ] Starting threat intelligence feeds', type: 'success' as const, duration: 600 },
    { text: '[ OK ] Loading Tartarus EDR: Kernel Shield ACTIVE', type: 'success' as const, duration: 750 },
    { text: '[ OK ] Initializing vulnerability scanner: OpenVAS', type: 'success' as const, duration: 800 },
    { text: '[ OK ] Loading penetration testing tools', type: 'success' as const, duration: 700 },
    { text: '[ OK ] Starting network analysis: Wireshark', type: 'success' as const, duration: 600 },
    { text: '[ OK ] Initializing exploit framework: Metasploit', type: 'success' as const, duration: 900 },
    { text: '[ OK ] Loading forensics toolkit: Autopsy', type: 'success' as const, duration: 700 },
    { text: '[ OK ] Starting reverse engineering suite', type: 'success' as const, duration: 800 },
    { text: '[ OK ] Portfolio interface ready', type: 'success' as const, duration: 600 },
    { text: '[ OK ] ADNAN OS fully operational - Welcome, Root', type: 'success' as const, duration: 1000 },
  ];
  
  useEffect(() => {
    setTimeout(() => setShowDragon(false), 2000);
  }, []);
  
  useEffect(() => {
    if (stage < bootSequence.length) {
      const current = bootSequence[stage];
      const timer = setTimeout(() => {
        setBootLogs(prev => [...prev, { text: current.text, type: current.type }]);
        setProgress(((stage + 1) / bootSequence.length) * 100);
        setStage(stage + 1);
      }, current.duration);
      
      return () => clearTimeout(timer);
    } else {
      setTimeout(onComplete, 1500);
    }
  }, [stage]);
  
  return (
    <AnimatePresence>
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 bg-black flex items-center justify-center overflow-hidden"
      >
        {/* Kali Dragon Logo */}
        {showDragon && (
          <motion.div
            initial={{ scale: 0, rotate: -180 }}
            animate={{ scale: 1, rotate: 0 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ duration: 1, type: "spring" }}
            className="absolute inset-0 flex items-center justify-center z-10"
          >
            <div className="text-center">
              <motion.div
                animate={{ 
                  filter: ["drop-shadow(0 0 20px #00ff00)", "drop-shadow(0 0 40px #00ff00)", "drop-shadow(0 0 20px #00ff00)"],
                  scale: [1, 1.05, 1]
                }}
                transition={{ duration: 2, repeat: Infinity }}
                className="text-9xl mb-4"
              >
                🐉
              </motion.div>
              <motion.h1 
                className="text-6xl font-black text-green-500 font-mono"
                animate={{ opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                ADNAN OS
              </motion.h1>
              <p className="text-green-400 font-mono text-sm mt-2">The quieter you become, the more you can hear...</p>
            </div>
          </motion.div>
        )}
        
        {!showDragon && (
          <div className="w-full max-w-6xl px-8">
            {/* BIOS Header */}
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8 flex items-center justify-between"
            >
              <div className="flex items-center gap-4">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
                >
                  <Shield className="text-green-500" size={48} />
                </motion.div>
                <div>
                  <h1 className="text-4xl font-black text-green-500 font-mono">ADNAN OS</h1>
                  <p className="text-sm font-mono text-green-400/60">Security-Enhanced Operating System | Build 20260127-KALI</p>
                </div>
              </div>
              <div className="text-right text-xs font-mono text-gray-500">
                <div>Intel i9-13900K @ 5.8GHz</div>
                <div>64GB DDR5-6000 RAM</div>
                <div>2TB NVMe Gen4 SSD</div>
              </div>
            </motion.div>
            
            {/* Boot Terminal */}
            <div className="bg-black border-2 border-green-500/30 rounded-lg overflow-hidden shadow-2xl shadow-green-500/20">
              <div className="bg-green-900/20 px-6 py-3 border-b border-green-500/30 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Terminal className="text-green-500" size={16} />
                  <span className="font-mono text-xs text-green-400">root@adnan-os:~# /boot/init</span>
                </div>
                <div className="flex gap-1">
                  <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  <div className="w-2 h-2 rounded-full bg-yellow-500" />
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                </div>
              </div>
              
              <div className="p-6 h-120 overflow-y-auto font-mono text-xs" style={{
                background: 'linear-gradient(180deg, #000000 0%, #001100 100%)'
              }}>
                <AnimatePresence mode="popLayout">
                  {bootLogs.map((log, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.2 }}
                      className={`mb-1.5 flex items-start gap-2 ${
                        log.type === 'success' ? 'text-green-400' :
                        log.type === 'error' ? 'text-red-400' :
                        log.type === 'warning' ? 'text-yellow-400' :
                        'text-cyan-400'
                      }`}
                    >
                      {log.type === 'success' && <Check size={12} className="mt-0.5 shrink-0" />}
                      {log.type === 'info' && <Loader size={12} className="mt-0.5 animate-spin shrink-0" />}
                      {log.type === 'warning' && <AlertTriangle size={12} className="mt-0.5 shrink-0" />}
                      {log.type === 'error' && <X size={12} className="mt-0.5 shrink-0" />}
                      <span className="flex-1">{log.text}</span>
                    </motion.div>
                  ))}
                </AnimatePresence>
                
                {stage < bootSequence.length && (
                  <motion.div
                    animate={{ opacity: [1, 0.5, 1] }}
                    transition={{ duration: 0.8, repeat: Infinity }}
                    className="text-green-400 flex items-center gap-2 mt-2"
                  >
                    <RefreshCw size={12} className="animate-spin" />
                    <span>Initializing system components...</span>
                  </motion.div>
                )}
              </div>
              
              {/* Progress Bar */}
              <div className="px-6 py-4 border-t border-green-500/20 bg-green-900/10">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono text-green-400">BOOT PROGRESS</span>
                  <span className="text-xs font-mono text-white font-bold">{Math.round(progress)}%</span>
                </div>
                <div className="h-3 bg-black rounded-full overflow-hidden border border-green-500/30">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    className="h-full bg-linear-to-r from-green-500 via-green-400 to-emerald-500 relative"
                    transition={{ duration: 0.5, ease: 'easeOut' }}
                  >
                    <motion.div
                      className="absolute inset-0 bg-linear-to-r from-transparent via-white to-transparent opacity-40"
                      animate={{ x: ['-100%', '200%'] }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                    />
                  </motion.div>
                </div>
                
                {/* System Stats Grid */}
                <div className="grid grid-cols-5 gap-3 mt-4">
                  {[
                    { label: 'CPU', value: Math.min(35 + stage * 4, 94), color: 'cyan' },
                    { label: 'RAM', value: Math.min(28 + stage * 5, 86), color: 'purple' },
                    { label: 'DISK', value: Math.min(15 + stage * 6, 78), color: 'green' },
                    { label: 'NET', value: Math.min(40 + stage * 4, 92), color: 'yellow' },
                    { label: 'SEC', value: Math.min(90 + stage * 0.5, 100), color: 'red' }
                  ].map((stat, i) => (
                    <div key={i} className="text-center">
                      <div className="text-[9px] font-mono text-gray-500 mb-1">{stat.label}</div>
                      <div className={`text-sm font-bold text-${stat.color}-400`}>{Math.round(stat.value)}%</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            
            {/* Loading Animation */}
            <motion.div className="mt-6 flex items-center justify-center gap-2">
              {[0, 1, 2, 3, 4, 5, 6].map((i) => (
                <motion.div
                  key={i}
                  className="w-2 h-2 bg-green-500 rounded-full"
                  animate={{
                    scale: [1, 1.8, 1],
                    opacity: [0.3, 1, 0.3],
                  }}
                  transition={{
                    duration: 1.4,
                    repeat: Infinity,
                    delay: i * 0.15,
                  }}
                />
              ))}
            </motion.div>
          </div>
        )}
      </motion.div>
    </AnimatePresence>
  );
};

// ==================== ULTRA 3D GLOBE (ENHANCED) ====================
const Ultra3DGlobe = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const [stats, setStats] = useState({ connections: 0, packets: 0, threats: 0 });
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    canvas.width = 550;
    canvas.height = 550;
    
    let rotation = 0;
    let mouseX = 0.5;
    const radius = 200;
    const centerX = 275;
    const centerY = 275;
    
    // Enhanced cities with real-time data simulation
    const cities = [
      { name: 'Jakarta', lat: -6.2, lon: 106.8, color: '#06b6d4', pulse: 0, connections: 234, packets: 1024 },
      { name: 'Singapore', lat: 1.3, lon: 103.8, color: '#10b981', pulse: 0, connections: 456, packets: 2048 },
      { name: 'Tokyo', lat: 35.7, lon: 139.7, color: '#f59e0b', pulse: 0, connections: 678, packets: 4096 },
      { name: 'New York', lat: 40.7, lon: -74.0, color: '#ef4444', pulse: 0, connections: 890, packets: 8192 },
      { name: 'London', lat: 51.5, lon: -0.1, color: '#8b5cf6', pulse: 0, connections: 567, packets: 3072 },
      { name: 'Sydney', lat: -33.9, lon: 151.2, color: '#ec4899', pulse: 0, connections: 345, packets: 1536 },
      { name: 'Dubai', lat: 25.2, lon: 55.3, color: '#f97316', pulse: 0, connections: 432, packets: 2560 },
      { name: 'Mumbai', lat: 19.1, lon: 72.9, color: '#14b8a6', pulse: 0, connections: 321, packets: 1792 },
    ];
    
    // Particle system
    const particles: Array<{x: number, y: number, z: number, speed: number, opacity: number, color: string}> = [];
    for (let i = 0; i < 150; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = radius + Math.random() * 40;
      particles.push({
        x: r * Math.sin(phi) * Math.cos(theta),
        y: r * Math.sin(phi) * Math.sin(theta),
        z: r * Math.cos(phi),
        speed: 0.008 + Math.random() * 0.015,
        opacity: Math.random(),
        color: ['#06b6d4', '#10b981', '#f59e0b'][Math.floor(Math.random() * 3)]
      });
    }
    
    let totalConnections = 0;
    let totalPackets = 0;
    
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = (e.clientX - rect.left) / rect.width;
    };
    
    canvas.addEventListener('mousemove', handleMouseMove);
    
    const drawGlobe = (time: number) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Outer atmosphere glow
      const outerGlow = ctx.createRadialGradient(centerX, centerY, radius * 0.6, centerX, centerY, radius * 2);
      outerGlow.addColorStop(0, 'rgba(6, 182, 212, 0)');
      outerGlow.addColorStop(0.5, 'rgba(6, 182, 212, 0.08)');
      outerGlow.addColorStop(0.8, 'rgba(6, 182, 212, 0.15)');
      outerGlow.addColorStop(1, 'rgba(6, 182, 212, 0)');
      ctx.fillStyle = outerGlow;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Draw particles with depth sorting
      const sortedParticles = particles.map((p, idx) => {
        const rotatedX = p.x * Math.cos(rotation * 0.01) - p.z * Math.sin(rotation * 0.01);
        const rotatedZ = p.x * Math.sin(rotation * 0.01) + p.z * Math.cos(rotation * 0.01);
        return { ...p, rotatedX, rotatedZ, idx };
      }).sort((a, b) => a.rotatedZ - b.rotatedZ);
      
      sortedParticles.forEach(p => {
        if (p.rotatedZ > 0) {
          const scale = 1 + p.rotatedZ / radius * 0.6;
          const x = centerX + p.rotatedX;
          const y = centerY + p.y;
          
          ctx.beginPath();
          ctx.arc(x, y, 1.5 * scale, 0, Math.PI * 2);
          ctx.fillStyle = `${p.color}${Math.floor(p.opacity * 80).toString(16).padStart(2, '0')}`;
          ctx.shadowColor = p.color;
          ctx.shadowBlur = 4 * scale;
          ctx.fill();
          ctx.shadowBlur = 0;
        }
        
        p.x += p.speed * Math.sin(time * 0.0008);
        p.y += p.speed * Math.cos(time * 0.0008);
        p.opacity = 0.3 + Math.sin(time * 0.002 + particles[p.idx].x) * 0.4;
      });
      
      // Draw main globe sphere
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      
      const sphereGradient = ctx.createRadialGradient(
        centerX - radius * 0.4, centerY - radius * 0.4, 0,
        centerX, centerY, radius * 1.2
      );
      sphereGradient.addColorStop(0, 'rgba(6, 182, 212, 0.25)');
      sphereGradient.addColorStop(0.4, 'rgba(6, 182, 212, 0.12)');
      sphereGradient.addColorStop(0.7, 'rgba(6, 182, 212, 0.06)');
      sphereGradient.addColorStop(1, 'rgba(0, 0, 0, 0.3)');
      ctx.fillStyle = sphereGradient;
      ctx.fill();
      
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.5)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
      
      // Grid lines with enhanced perspective
      for (let lat = -75; lat <= 75; lat += 15) {
        ctx.beginPath();
        const y = centerY - (lat / 90) * radius * 0.95;
        const latRad = (lat * Math.PI) / 180;
        const width = Math.cos(latRad) * radius;
        
        for (let lon = -180; lon <= 180; lon += 2) {
          const adjustedLon = lon + rotation + (mouseX - 0.5) * 40;
          const lonRad = (adjustedLon * Math.PI) / 180;
          const x = centerX + Math.sin(lonRad) * width;
          const z = Math.cos(lonRad);
          
          if (z > 0.1) {
            if (lon === -180) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
          }
        }
        
        const opacity = 0.12 + Math.abs(lat) / 90 * 0.12;
        ctx.strokeStyle = `rgba(6, 182, 212, ${opacity})`;
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }
      
      // Longitude lines
      for (let lon = 0; lon < 360; lon += 15) {
        ctx.beginPath();
        
        for (let lat = -90; lat <= 90; lat += 2) {
          const adjustedLon = lon + rotation + (mouseX - 0.5) * 40;
          const latRad = (lat * Math.PI) / 180;
          const lonRad = (adjustedLon * Math.PI) / 180;
          
          const y = centerY - Math.sin(latRad) * radius;
          const width = Math.cos(latRad) * radius;
          const x = centerX + Math.sin(lonRad) * width;
          const z = Math.cos(lonRad);
          
          if (z > 0.1) {
            if (lat === -90) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
          }
        }
        
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.10)';
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      
      // Enhanced city rendering
      totalConnections = 0;
      totalPackets = 0;
      
      cities.forEach((city, idx) => {
        const adjustedLon = city.lon + rotation + (mouseX - 0.5) * 40;
        const latRad = (city.lat * Math.PI) / 180;
        const lonRad = (adjustedLon * Math.PI) / 180;
        
        const x = centerX + Math.sin(lonRad) * Math.cos(latRad) * radius;
        const y = centerY - Math.sin(latRad) * radius;
        const z = Math.cos(lonRad) * Math.cos(latRad);
        
        if (z > 0.2) {
          totalConnections += city.connections;
          totalPackets += city.packets;
          
          city.pulse = (city.pulse + 0.06) % (Math.PI * 2);
          const pulseSize = 4 + Math.sin(city.pulse) * 2.5;
          
          // Multi-layer glow
          for (let i = 3; i >= 1; i--) {
            ctx.beginPath();
            ctx.arc(x, y, pulseSize * (i + 1), 0, Math.PI * 2);
            const glowGradient = ctx.createRadialGradient(x, y, 0, x, y, pulseSize * (i + 1));
            glowGradient.addColorStop(0, `${city.color}${Math.floor(60 / i).toString(16).padStart(2, '0')}`);
            glowGradient.addColorStop(1, `${city.color}00`);
            ctx.fillStyle = glowGradient;
            ctx.fill();
          }
          
          // City marker
          ctx.beginPath();
          ctx.arc(x, y, pulseSize, 0, Math.PI * 2);
          ctx.fillStyle = city.color;
          ctx.shadowColor = city.color;
          ctx.shadowBlur = 20;
          ctx.fill();
          ctx.shadowBlur = 0;
          
          // Connection to center with animated pulse
          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(centerX, centerY);
          ctx.strokeStyle = `${city.color}20`;
          ctx.lineWidth = 2;
          ctx.stroke();
          
          // Data packets animation
          const numPackets = 3;
          for (let p = 0; p < numPackets; p++) {
            const packetProgress = ((time * 0.0012 + idx * 0.25 + p * 0.3) % 1);
            const packetX = x + (centerX - x) * packetProgress;
            const packetY = y + (centerY - y) * packetProgress;
            const packetSize = 2.5 + Math.sin(packetProgress * Math.PI) * 1.5;
            
            ctx.beginPath();
            ctx.arc(packetX, packetY, packetSize, 0, Math.PI * 2);
            ctx.fillStyle = city.color;
            ctx.shadowColor = city.color;
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;
          }
          
          // Enhanced city label
          if (z > 0.4) {
            ctx.save();
            ctx.fillStyle = city.color;
            ctx.font = 'bold 12px JetBrains Mono';
            ctx.shadowColor = 'black';
            ctx.shadowBlur = 8;
            ctx.fillText(city.name, x + 14, y - 10);
            
            // Connection count
            ctx.font = '9px JetBrains Mono';
            ctx.fillStyle = `${city.color}cc`;
            ctx.fillText(`${city.connections} conn`, x + 14, y + 2);
            ctx.shadowBlur = 0;
            ctx.restore();
          }
        }
      });
      
      // Update stats
      setStats({
        connections: totalConnections,
        packets: totalPackets,
        threats: Math.floor(Math.random() * 50)
      });
      
      // Animated core
      const coreSize = 12 + Math.sin(time * 0.004) * 4;
      ctx.beginPath();
      ctx.arc(centerX, centerY, coreSize, 0, Math.PI * 2);
      const coreGradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, coreSize * 1.5);
      coreGradient.addColorStop(0, 'rgba(6, 182, 212, 1)');
      coreGradient.addColorStop(0.4, 'rgba(6, 182, 212, 0.9)');
      coreGradient.addColorStop(0.7, 'rgba(6, 182, 212, 0.5)');
      coreGradient.addColorStop(1, 'rgba(6, 182, 212, 0)');
      ctx.fillStyle = coreGradient;
      ctx.shadowColor = 'rgba(6, 182, 212, 1)';
      ctx.shadowBlur = 30;
      ctx.fill();
      ctx.shadowBlur = 0;
      
      rotation += 0.18 + (mouseX - 0.5) * 0.12;
      requestAnimationFrame(() => drawGlobe(time + 16));
    };
    
    drawGlobe(0);
    setTimeout(() => setIsLoaded(true), 1200);
    
    return () => {
      canvas.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);
  
  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.85, rotateY: -30 }}
      animate={{ opacity: isLoaded ? 1 : 0.6, scale: isLoaded ? 1 : 0.85, rotateY: 0 }}
      transition={{ duration: 1.2, type: "spring" }}
      className="relative"
    >
      <canvas ref={canvasRef} className="w-full h-full" style={{ filter: 'drop-shadow(0 0 40px rgba(6, 182, 212, 0.3))' }} />
      
      {/* Real-time stats overlay */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: isLoaded ? 1 : 0, y: isLoaded ? 0 : 20 }}
        transition={{ delay: 0.5 }}
        className="absolute bottom-6 left-1/2 transform -translate-x-1/2 w-full max-w-md"
      >
        <div className="bg-black/80 border-2 border-cyan-500/30 rounded-xl p-4 backdrop-blur-xl">
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-cyan-400 font-mono text-xs mb-1">ACTIVE CONNECTIONS</div>
              <div className="text-white font-bold text-2xl font-mono">{stats.connections}</div>
            </div>
            <div>
              <div className="text-green-400 font-mono text-xs mb-1">PACKETS/SEC</div>
              <div className="text-white font-bold text-2xl font-mono">{stats.packets}</div>
            </div>
            <div>
              <div className="text-red-400 font-mono text-xs mb-1">THREATS BLOCKED</div>
              <div className="text-white font-bold text-2xl font-mono">{stats.threats}</div>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-center gap-2">
            <motion.div 
              className="w-2 h-2 bg-green-500 rounded-full"
              animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
            <span className="text-green-400 font-mono text-xs">NETWORK STATUS: OPTIMAL</span>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

// ==================== MATRIX RAIN (ENHANCED) ====================
const EnhancedMatrixRain = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops: number[] = [];
    
    for (let i = 0; i < columns; i++) drops[i] = Math.random() * -100;
    
    const draw = () => {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${fontSize}px monospace`;
      
      for (let i = 0; i < drops.length; i++) {
        const text = chars[Math.floor(Math.random() * chars.length)];
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        
        const opacity = Math.min(1, drops[i] / 20);
        ctx.fillStyle = `rgba(0, 255, 65, ${opacity * 0.35})`;
        ctx.fillText(text, x, y);
        
        if (drops[i] * fontSize > 0 && drops[i] < 8) {
          ctx.fillStyle = '#00ff41';
          ctx.shadowColor = '#00ff41';
          ctx.shadowBlur = 10;
          ctx.fillText(text, x, y);
          ctx.shadowBlur = 0;
        }
        
        if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    };
    
    const interval = setInterval(draw, 45);
    const handleResize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    window.addEventListener('resize', handleResize);
    
    return () => { clearInterval(interval); window.removeEventListener('resize', handleResize); };
  }, []);
  
  return <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none opacity-[0.15] z-0" />;
};

// ==================== PARTICLE NETWORK ====================
const ParticleNetwork = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    class Particle {
      x: number; y: number; vx: number; vy: number; size: number; opacity: number; color: string;
      
      constructor() {
        this.x = Math.random() * (canvas?.width || 800);
        this.y = Math.random() * (canvas?.height || 600);
        this.vx = (Math.random() - 0.5) * 0.6;
        this.vy = (Math.random() - 0.5) * 0.6;
        this.size = Math.random() * 2.5 + 1;
        this.opacity = Math.random() * 0.5 + 0.3;
        this.color = ['#06b6d4', '#10b981', '#f59e0b'][Math.floor(Math.random() * 3)];
      }
      
      update() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > (canvas?.width || 800)) this.vx *= -1;
        if (this.y < 0 || this.y > (canvas?.height || 600)) this.vy *= -1;
      }
      
      draw() {
        if (!ctx) return;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = `${this.color}${Math.floor(this.opacity * 255).toString(16).padStart(2, '0')}`;
        ctx.shadowColor = this.color;
        ctx.shadowBlur = 5;
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
    
    const particles: Particle[] = [];
    for (let i = 0; i < 120; i++) particles.push(new Particle());
    
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      particles.forEach((p, i) => {
        p.update();
        p.draw();
        
        particles.slice(i + 1).forEach(p2 => {
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          if (distance < 140) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(6, 182, 212, ${0.18 * (1 - distance / 140)})`;
            ctx.lineWidth = 1.2;
            ctx.stroke();
          }
        });
      });
      
      requestAnimationFrame(animate);
    };
    
    animate();
    
    const handleResize = () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);
  
  return <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none opacity-25 z-0" />;
};

// ==================== GLITCH TEXT ====================
const GlitchText = ({ children, className = "" }: any) => (
  <span className={`relative inline-block ${className}`}>
    <span className="relative z-10">{children}</span>
    <span className="absolute top-0 left-0 -translate-x-0.5 text-cyan-500 opacity-70 animate-glitch-1">{children}</span>
    <span className="absolute top-0 left-0 translate-x-0.5 text-green-500 opacity-70 animate-glitch-2">{children}</span>
  </span>
);

// ==================== HOLOGRAPHIC CARD ====================
const HolographicCard = ({ children, className = "" }: any) => {
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [7, -7]), { stiffness: 100, damping: 15 });
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-7, 7]), { stiffness: 100, damping: 15 });
  
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    x.set((e.clientX - centerX) / rect.width);
    y.set((e.clientY - centerY) / rect.height);
  };
  
  return (
    <motion.div
      onMouseMove={handleMouseMove}
      onMouseLeave={() => { x.set(0); y.set(0); }}
      style={{ rotateX, rotateY, transformStyle: "preserve-3d" }}
      className={`relative ${className}`}
    >
      {children}
    </motion.div>
  );
};

// ==================== SYSTEM MONITOR ====================
const SystemMonitor = () => {
  const [metrics, setMetrics] = useState<SystemMetrics>({
    cpu: 45, ram: 62, disk: 78, network: 234, processes: 387, uptime: '327d 14h'
  });
  
  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics({
        cpu: 30 + Math.random() * 45,
        ram: 50 + Math.random() * 35,
        disk: 70 + Math.random() * 20,
        network: 180 + Math.random() * 120,
        processes: 350 + Math.floor(Math.random() * 100),
        uptime: '327d 14h'
      });
    }, 2500);
    return () => clearInterval(interval);
  }, []);
  
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      {[
        { icon: Activity, label: 'CPU', value: `${metrics.cpu.toFixed(1)}%`, color: 'cyan', max: 100 },
        { icon: Database, label: 'RAM', value: `${metrics.ram.toFixed(1)}%`, color: 'purple', max: 100 },
        { icon: Database, label: 'DISK', value: `${metrics.disk.toFixed(1)}%`, color: 'green', max: 100 },
        { icon: Activity, label: 'NET', value: `${metrics.network.toFixed(0)} MB/s`, color: 'yellow', max: 300 },
        { icon: Server, label: 'PROC', value: metrics.processes.toString(), color: 'orange', max: 500 },
        { icon: Server, label: 'UPTIME', value: metrics.uptime, color: 'cyan', max: 0 },
      ].map((stat, i) => {
        const Icon = stat.icon;
        const percentage = stat.max > 0 ? (parseFloat(stat.value) / stat.max) * 100 : 100;
        
        return (
          <motion.div 
            key={i}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.08 }}
            whileHover={{ scale: 1.05, boxShadow: `0 0 30px rgba(6, 182, 212, 0.3)` }}
            className="p-5 bg-zinc-900/60 border-2 border-cyan-500/30 rounded-xl hover:border-cyan-500/60 transition-all"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Icon className={`text-${stat.color}-400`} size={18} />
                <span className="text-xs font-mono text-gray-400 uppercase">{stat.label}</span>
              </div>
              <span className="text-sm font-bold text-white font-mono">{stat.value}</span>
            </div>
            {stat.max > 0 && (
              <div className="h-2 bg-zinc-800 rounded-full overflow-hidden border border-cyan-500/20">
                <motion.div 
                  className={`h-full bg-linear-to-r from-${stat.color}-500 to-${stat.color}-400`}
                  initial={{ width: 0 }}
                  animate={{ width: `${percentage}%` }}
                  transition={{ duration: 0.8, type: "spring" }}
                />
              </div>
            )}
          </motion.div>
        );
      })}
    </div>
  );
};

// ==================== ADVANCED TERMINAL ====================
const AdvancedTerminal = ({ onRootAccess, onScanTrigger, isRoot }: any) => {
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [output, setOutput] = useState<any[]>([
    { type: 'output', text: '╔══════════════════════════════════════════════════════╗' },
    { type: 'output', text: '║     ADNAN OS SECURE TERMINAL v4.2.0-KALI            ║' },
    { type: 'output', text: '║     Kernel 6.12.0-ebpf | Architecture: x86_64       ║' },
    { type: 'output', text: '╚══════════════════════════════════════════════════════╝' },
    { type: 'output', text: '' },
    { type: 'success', text: '[+] Security protocols: ACTIVE' },
    { type: 'success', text: '[+] Firewall: ENABLED' },
    { type: 'output', text: '' },
    { type: 'output', text: 'Type "help" for available commands or "man <command>" for details' },
    { type: 'output', text: '' },
  ]);
  const outputRef = useRef<HTMLDivElement>(null);
  
  const addOutput = (lines: any[]) => setOutput(prev => [...prev, ...lines]);
  
  const commands: Record<string, () => void> = {
    help: () => addOutput([
      { type: 'success', text: '╔════════════════════════════════════════════════════════╗' },
      { type: 'success', text: '║              AVAILABLE COMMANDS                        ║' },
      { type: 'success', text: '╠════════════════════════════════════════════════════════╣' },
      { type: 'output', text: '║  help       - Display this help message                ║' },
      { type: 'output', text: '║  clear      - Clear terminal screen                    ║' },
      { type: 'output', text: '║  whoami     - Display current user information         ║' },
      { type: 'output', text: '║  ls         - List directory contents                  ║' },
      { type: 'output', text: '║  pwd        - Print working directory                  ║' },
      { type: 'output', text: '║  scan       - Initiate comprehensive security scan     ║' },
      { type: 'output', text: '║  sudo su    - Attempt privilege escalation             ║' },
      { type: 'output', text: '║  neofetch   - Display system information               ║' },
      { type: 'output', text: '║  hack       - Initialize breach protocol (DEMO)        ║' },
      { type: 'output', text: '║  nmap       - Network mapper simulation                ║' },
      { type: 'output', text: '║  metasploit - Launch exploit framework                 ║' },
      { type: 'output', text: '║  wireshark  - Start packet analyzer                    ║' },
      { type: 'output', text: '║  sysinfo    - Detailed system diagnostics              ║' },
      { type: 'output', text: '║  about      - About Adnan Syukur                       ║' },
      { type: 'output', text: '║  tartarus   - Deep dive: Tartarus EDR architecture     ║' },
      { type: 'success', text: '╚════════════════════════════════════════════════════════╝' },
      { type: 'output', text: '' },
    ]),
    clear: () => setOutput([]),
    whoami: () => addOutput([
      { type: 'success', text: isRoot ? '┌─[root@adnan-os]' : '┌─[guest@adnan-os]' },
      { type: 'success', text: isRoot ? '└──╼ $ uid=0(root) gid=0(root) groups=0(root)' : '└──╼ $ uid=1000(guest) gid=1000(guest)' },
      { type: 'output', text: '' },
    ]),
    pwd: () => addOutput([{ type: 'output', text: isRoot ? '/root' : '/home/guest/portfolio' }, { type: 'output', text: '' }]),
    ls: () => addOutput([
      { type: 'output', text: 'total 64K' },
      { type: 'output', text: 'drwxr-xr-x  9 adnan users  4.0K Jan 27 15:30 projects/' },
      { type: 'output', text: 'drwx------  2 adnan users  4.0K Jan 27 15:28 .credentials/' },
      { type: 'output', text: '-rw-r--r--  1 adnan users  2.3K Jan 27 15:29 portfolio.md' },
      { type: 'output', text: '-rwxr-xr-x  1 adnan users  9.1K Jan 27 15:30 deploy.sh' },
      { type: 'output', text: '-rw-------  1 adnan users  4.2K Jan 27 15:27 .ssh_keys' },
      { type: 'output', text: '' },
    ]),
    scan: () => {
      addOutput([
        { type: 'success', text: '[*] Initiating comprehensive security scan...' },
        { type: 'output', text: '[*] Phase 1: Network topology analysis...' },
        { type: 'output', text: '[*] Phase 2: Port enumeration (1-65535)...' },
        { type: 'output', text: '[*] Phase 3: Service fingerprinting...' },
        { type: 'output', text: '[*] Phase 4: Vulnerability assessment...' },
        { type: 'success', text: '[+] Scan complete!' },
        { type: 'success', text: `[+] Results: ${STATIC_PROJECTS.length} projects | 0 vulnerabilities | 100% secure` },
        { type: 'warning', text: '[!] Kernel-class threats detected and neutralized by Tartarus EDR' },
        { type: 'output', text: '' },
      ]);
      onScanTrigger();
    },
    'sudo su': () => {
      if (isRoot) {
        addOutput([{ type: 'warning', text: '[!] Already running as root.' }, { type: 'output', text: '' }]);
      } else {
        addOutput([
          { type: 'output', text: '[sudo] password for guest: ****************' },
          { type: 'output', text: '[*] Verifying credentials...' },
          { type: 'success', text: '[+] Authentication successful!' },
          { type: 'success', text: '[+] Privilege escalation complete!' },
          { type: 'success', text: '' },
          { type: 'success', text: '╔═══════════════════════════════════════════╗' },
          { type: 'success', text: '║  ROOT ACCESS GRANTED                      ║' },
          { type: 'success', text: '║  Full system control enabled              ║' },
          { type: 'success', text: '╚═══════════════════════════════════════════╝' },
          { type: 'output', text: '' },
        ]);
        onRootAccess();
      }
    },
    neofetch: () => addOutput([
      { type: 'output', text: '           ▗▄▄▄▄▄▄▄       adnan@adnan-os' },
      { type: 'output', text: '          ▄▛▀▀▀▀▀▀▀▜▖     ───────────────────────────' },
      { type: 'output', text: '         ▐▌         ▐▌    OS: AdnanOS 4.2.0 x86_64' },
      { type: 'output', text: '        ▗▘▝▀▀▀▀▀▀▀▀▀▘▐    Host: Secure Workstation Pro' },
      { type: 'output', text: '        ▐    ▄▄▄▄▄   ▐    Kernel: 6.12.0-ebpf-hardened' },
      { type: 'output', text: '        ▐   ▐██████▌ ▐    Uptime: 327 days, 14 hours' },
      { type: 'output', text: '        ▐   ▐██████▌ ▐    Shell: zsh 5.9 with oh-my-zsh' },
      { type: 'output', text: '        ▝▀▀▀▝▀▀▀▀▀▀▀▀     Terminal: secure-term' },
      { type: 'output', text: '                          CPU: Intel i9-13900K @ 5.8GHz' },
      { type: 'output', text: '                          GPU: NVIDIA RTX 4090 24GB' },
      { type: 'output', text: '                          Memory: 12.8GB / 64GB' },
      { type: 'output', text: '                          EDR: Tartarus Kernel Shield v1.0' },
      { type: 'warning', text: '                          Lang: C/eBPF, Rust, Python, Node.js' },
      { type: 'output', text: '' },
    ]),
    hack: () => addOutput([
      { type: 'success', text: '[*] Initializing breach protocol (DEMONSTRATION)...' },
      { type: 'output', text: '[*] Target: portfolio.demo.local:443' },
      { type: 'success', text: '[+] Connection established!' },
      { type: 'output', text: '[*] Bypassing WAF rules...' },
      { type: 'success', text: '[+] WAF bypassed!' },
      { type: 'output', text: '[*] Exploiting CVE-2024-DEMO...' },
      { type: 'success', text: '[+] Exploit successful!' },
      { type: 'success', text: '[+] Root shell obtained!' },
      { type: 'warning', text: '[!] This is a simulation for demonstration only.' },
      { type: 'output', text: '' },
    ]),
    nmap: () => addOutput([
      { type: 'output', text: 'Starting Nmap 7.94 ( https://nmap.org )' },
      { type: 'output', text: 'Nmap scan report for portfolio.local (192.168.1.100)' },
      { type: 'output', text: 'Host is up (0.00012s latency).' },
      { type: 'output', text: 'PORT     STATE SERVICE' },
      { type: 'output', text: '22/tcp   open  ssh' },
      { type: 'output', text: '80/tcp   open  http' },
      { type: 'output', text: '443/tcp  open  https' },
      { type: 'output', text: '3000/tcp open  ppp' },
      { type: 'output', text: '' },
    ]),
    metasploit: () => addOutput([
      { type: 'success', text: '      =[ metasploit v6.3.45-dev                         ]' },
      { type: 'success', text: '+ -- --=[ 2357 exploits - 1234 auxiliary - 409 post     ]' },
      { type: 'success', text: '+ -- --=[ 1235 payloads - 46 encoders - 11 nops         ]' },
      { type: 'success', text: 'msf6 > use exploit/multi/handler' },
      { type: 'output', text: 'msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp' },
      { type: 'success', text: '[+] Framework initialized successfully' },
      { type: 'output', text: '' },
    ]),
    wireshark: () => addOutput([
      { type: 'success', text: '[+] Wireshark packet analyzer starting...' },
      { type: 'output', text: '[*] Capturing on interface: eth0' },
      { type: 'output', text: '[*] Packets captured: 1,245' },
      { type: 'output', text: '[*] Display filter: tcp.port == 443' },
      { type: 'success', text: '[+] Analysis ready' },
      { type: 'output', text: '' },
    ]),
    sysinfo: () => addOutput([
      { type: 'success', text: '╔═══════════════════════════════════════════════════╗' },
      { type: 'success', text: '║         COMPREHENSIVE SYSTEM DIAGNOSTICS          ║' },
      { type: 'success', text: '╠═══════════════════════════════════════════════════╣' },
      { type: 'output', text: '║  Hostname:       adnan-os                         ║' },
      { type: 'output', text: '║  OS Version:     AdnanOS 4.2.0 LTS (Kali-based)  ║' },
      { type: 'output', text: '║  Kernel:         6.12.0-ebpf-hardened            ║' },
      { type: 'output', text: '║  Architecture:   x86_64                           ║' },
      { type: 'output', text: '║  Processor:      Intel Core i9-13900K            ║' },
      { type: 'output', text: '║  Security:       SELinux Enforcing + eBPF LSM    ║' },
      { type: 'output', text: '║  Firewall:       nftables + Fail2ban Active      ║' },
      { type: 'warning', text: '║  EDR:            Tartarus Kernel Shield v1.0     ║' },
      { type: 'output', text: '║  Languages:      C/eBPF, Rust, Python, Node.js   ║' },
      { type: 'success', text: '╚═══════════════════════════════════════════════════╝' },
      { type: 'output', text: '' },
    ]),
    about: () => addOutput([
      { type: 'success', text: '╔════════════════════════════════════════════════════════════════╗' },
      { type: 'success', text: '║                    ADNAN SYUKUR                                ║' },
      { type: 'success', text: '╠════════════════════════════════════════════════════════════════╣' },
      { type: 'output', text: '║  Title:         Security Engineer & Full-Stack Developer      ║' },
      { type: 'output', text: '║  Focus:         Kernel Security, eBPF, Penetration Testing   ║' },
      { type: 'output', text: '║  Certs:         BNSP Rank 1, DB Developer, VAPT               ║' },
      { type: 'output', text: '║  Institution:   Universitas Siber Indonesia                   ║' },
      { type: 'output', text: '║  Position:      Vice President, Student Association           ║' },
      { type: 'output', text: '║  Skills:        C, eBPF, Rust, Linux Kernel, Python, Node.js  ║' },
      { type: 'output', text: '║  Projects:      11 Deployed | 3 Kernel-Native EDR Systems     ║' },
      { type: 'output', text: '║  GitHub:        github.com/SS7ZX                              ║' },
      { type: 'success', text: '╠════════════════════════════════════════════════════════════════╣' },
      { type: 'warning', text: '║  FLAGSHIP:      Tartarus EDR — Omniscient Kernel Shield       ║' },
      { type: 'warning', text: '║                 eBPF openat hook → bpf_send_signal(9)         ║' },
      { type: 'warning', text: '║                 Rust/Discord relay | Zero-leak policy         ║' },
      { type: 'success', text: '╚════════════════════════════════════════════════════════════════╝' },
      { type: 'output', text: '' },
      { type: 'success', text: '"The quieter you become, the more you can hear." - Kali Linux' },
      { type: 'output', text: '' },
    ]),
    tartarus: () => addOutput([
      { type: 'success', text: '╔════════════════════════════════════════════════════════════════╗' },
      { type: 'success', text: '║         🏛️  TARTARUS EDR — OMNISCIENT KERNEL SHIELD            ║' },
      { type: 'success', text: '╠════════════════════════════════════════════════════════════════╣' },
      { type: 'warning', text: '  ARCHITECTURAL GOLDEN PATH:' },
      { type: 'output',  text: '  [Ring 0] eBPF/C Infiltrator → hooks openat() syscall' },
      { type: 'output',  text: '  [Kernel] Enforcer → bpf_send_signal(9) before FD return' },
      { type: 'output',  text: '  [User]   Rust Control Plane → PID exclusion, lifecycle mgmt' },
      { type: 'success', text: '  [Cloud]  Discord Uplink → Rich Embed JSON, forum threads' },
      { type: 'success', text: '╠════════════════════════════════════════════════════════════════╣' },
      { type: 'warning', text: '  EXPERT FEATURES:' },
      { type: 'output',  text: '  ✓ Zero-Copy Telemetry via BPF Ring Buffer' },
      { type: 'output',  text: '  ✓ Threaded Forum Integration (bypasses 400 Bad Request)' },
      { type: 'output',  text: '  ✓ Multi-vector: /etc/shadow, SSH keys, sudoers' },
      { type: 'output',  text: '  ✓ tokio::spawn async Discord relay (non-blocking kernel)' },
      { type: 'output',  text: '  ✓ Cross-language safety: Rust ↔ C struct alignment' },
      { type: 'success', text: '╠════════════════════════════════════════════════════════════════╣' },
      { type: 'success', text: '  VERDICT: PROFESSIONAL GRADE ★★★★★' },
      { type: 'success', text: '╚════════════════════════════════════════════════════════════════╝' },
      { type: 'output',  text: '' },
    ]),
  };
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    
    addOutput([{ type: 'command', text: `${isRoot ? 'root@adnan-os:~#' : 'guest@adnan-os:~$'} ${input}` }]);
    setHistory(prev => [...prev, input]);
    setHistoryIndex(-1);
    
    const cmd = input.trim().toLowerCase();
    if (commands[cmd]) commands[cmd]();
    else addOutput([
      { type: 'error', text: `bash: ${input}: command not found` },
      { type: 'output', text: 'Type "help" for available commands' },
      { type: 'output', text: '' }
    ]);
    
    setInput('');
  };
  
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0) {
        const newIndex = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex !== -1) {
        const newIndex = historyIndex + 1;
        if (newIndex >= history.length) {
          setHistoryIndex(-1);
          setInput('');
        } else {
          setHistoryIndex(newIndex);
          setInput(history[newIndex]);
        }
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const availableCommands = Object.keys(commands);
      const matches = availableCommands.filter(cmd => cmd.startsWith(input.toLowerCase()));
      if (matches.length === 1) setInput(matches[0]);
      else if (matches.length > 1) addOutput([{ type: 'output', text: matches.join('  ') }, { type: 'output', text: '' }]);
    }
  };
  
  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [output]);
  
  return (
    <HolographicCard className="group">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="bg-black/95 border-2 border-green-500/40 rounded-xl overflow-hidden shadow-2xl shadow-green-500/20"
      >
        <div className="flex items-center gap-2 px-4 py-3 bg-linear-to-r from-green-900/30 to-emerald-900/30 border-b border-green-500/30">
          <Terminal className="text-green-500" size={18} />
          <span className="font-mono text-sm text-green-400 flex-1">KALI TERMINAL</span>
          <div className="flex gap-1">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
            <div className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
          </div>
        </div>
        
        <div ref={outputRef} className="font-mono text-xs h-105 overflow-y-auto p-4 bg-linear-to-b from-black via-black to-green-950/10">
          {output.map((line, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15 }}
              className={`mb-1 ${
                line.type === 'command' ? 'text-green-400 font-bold' :
                line.type === 'error' ? 'text-red-400' :
                line.type === 'success' ? 'text-green-400' :
                line.type === 'warning' ? 'text-yellow-400' :
                'text-gray-400'
              }`}
            >
              {line.text}
            </motion.div>
          ))}
        </div>
        
        <form onSubmit={handleSubmit} className="flex items-center gap-2 px-4 py-3 border-t border-green-500/20 bg-green-950/20">
          <span className={`font-mono text-xs font-bold ${isRoot ? 'text-red-500' : 'text-green-400'}`}>
            {isRoot ? 'root@adnan-os:~#' : 'guest@adnan-os:~$'}
          </span>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent border-none outline-none font-mono text-xs text-white placeholder-gray-600"
            placeholder="Enter command... (try 'help')"
            autoFocus
          />
        </form>
      </motion.div>
    </HolographicCard>
  );
};

// ==================== LIVE THREAT FEED ====================
const LiveThreatFeed = () => {
  const [threats, setThreats] = useState<ThreatAlert[]>([
    { id: 1, time: '15:42:18', level: 'HIGH', msg: 'SQL Injection attempt blocked', source: '203.45.12.88', blocked: true },
    { id: 2, time: '15:40:23', level: 'CRITICAL', msg: 'Brute force attack prevented', source: '45.142.67.23', blocked: true },
    { id: 3, time: '15:38:45', level: 'MEDIUM', msg: 'Suspicious API request detected', source: '104.28.9.15', blocked: true },
    { id: 4, time: '15:36:12', level: 'LOW', msg: 'Failed authentication attempt', source: '192.168.1.45', blocked: true },
  ]);
  
  useEffect(() => {
    const interval = setInterval(() => {
      const levels: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const messages = [
        'Port scan detected', 'DDoS attempt mitigated', 'Malware signature matched',
        'Unauthorized access blocked', 'Zero-day exploit prevented', 'Buffer overflow prevented',
        'Command injection blocked', 'XSS attack neutralized', 'CSRF token validated'
      ];
      
      const newThreat: ThreatAlert = {
        id: Date.now(),
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        level: levels[Math.floor(Math.random() * levels.length)],
        msg: messages[Math.floor(Math.random() * messages.length)],
        source: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        blocked: true
      };
      
      setThreats(prev => [newThreat, ...prev.slice(0, 7)]);
    }, 6000);
    
    return () => clearInterval(interval);
  }, []);
  
  return (
    <HolographicCard className="group">
      <div className="bg-black/95 border-2 border-red-500/40 rounded-xl overflow-hidden shadow-2xl shadow-red-500/20 h-130 flex flex-col">
        <div className="flex items-center gap-2 px-4 py-3 bg-linear-to-r from-red-900/30 to-orange-900/30 border-b border-red-500/30">
          <Radar className="text-red-500 animate-pulse" size={18} />
          <span className="font-mono text-sm text-red-400 flex-1">THREAT INTELLIGENCE</span>
          <motion.span 
            animate={{ opacity: [1, 0.5, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
            className="font-mono text-[10px] text-green-400 bg-green-500/10 px-2 py-1 rounded border border-green-500/30"
          >
            LIVE
          </motion.span>
        </div>
        
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <AnimatePresence mode="popLayout">
            {threats.map((threat) => (
              <motion.div
                key={threat.id}
                initial={{ opacity: 0, x: -20, height: 0 }}
                animate={{ opacity: 1, x: 0, height: 'auto' }}
                exit={{ opacity: 0, x: 20, height: 0 }}
                transition={{ duration: 0.3 }}
                className="p-4 bg-zinc-900/60 border-2 border-zinc-800 rounded-lg hover:border-red-500/40 transition-all"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-[10px] text-gray-500">{threat.time}</span>
                  <motion.span 
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className={`font-mono text-[9px] px-3 py-1 rounded-full ${
                      threat.level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-2 border-red-500/40 animate-pulse' :
                      threat.level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-2 border-orange-500/40' :
                      threat.level === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border-2 border-yellow-500/40' :
                      'bg-blue-500/20 text-blue-400 border-2 border-blue-500/40'
                    }`}
                  >
                    {threat.level}
                  </motion.span>
                </div>
                <p className="text-sm text-gray-300 mb-2 font-medium">{threat.msg}</p>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe size={12} className="text-cyan-400" />
                    <p className="font-mono text-[11px] text-cyan-400">{threat.source}</p>
                  </div>
                  {threat.blocked && (
                    <div className="flex items-center gap-1 text-green-400 text-[10px] font-mono">
                      <Check size={12} />
                      <span>BLOCKED</span>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>
    </HolographicCard>
  );
};

// ==================== PROJECT MODAL ====================
const ProjectModal = ({ project, onClose }: any) => (
  <AnimatePresence>
    {project && (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <motion.div 
          initial={{ opacity: 0 }} 
          animate={{ opacity: 1 }} 
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-black/95 backdrop-blur-2xl"
        />
        
        <motion.div 
          initial={{ scale: 0.85, opacity: 0, y: 30, rotateX: 15 }}
          animate={{ scale: 1, opacity: 1, y: 0, rotateX: 0 }}
          exit={{ scale: 0.85, opacity: 0, y: 30, rotateX: 15 }}
          transition={{ type: "spring", damping: 20, stiffness: 100 }}
          className="relative w-full max-w-5xl max-h-[90vh] overflow-hidden z-10"
        >
          <div className="bg-black border-2 border-cyan-500/40 rounded-2xl overflow-hidden shadow-2xl shadow-cyan-500/30">
            {/* Header */}
            <div className="bg-linear-to-r from-cyan-900/40 to-purple-900/40 p-6 border-b-2 border-cyan-500/30 backdrop-blur-sm">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <motion.div 
                    animate={{ rotate: [0, 360] }}
                    transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                    className="p-3 bg-cyan-500/10 border-2 border-cyan-500/40 rounded-xl"
                  >
                    <Shield className="text-cyan-400" size={32} />
                  </motion.div>
                  <div>
                    <h2 className="text-3xl font-black text-white mb-1">
                      <GlitchText>{project.title}</GlitchText>
                    </h2>
                    <p className="text-sm font-mono text-cyan-400">COMPREHENSIVE SECURITY AUDIT REPORT</p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-3 bg-red-500/10 hover:bg-red-500/20 border-2 border-red-500/40 rounded-xl transition-all group"
                >
                  <X className="text-red-400 group-hover:rotate-90 transition-transform duration-300" size={22} />
                </button>
              </div>
            </div>
            
            {/* Content */}
            <div className="overflow-y-auto max-h-[calc(90vh-180px)] p-8 bg-linear-to-b from-black via-zinc-950 to-black">
              <div className="space-y-6">
                {/* Security Level */}
                <div className="flex items-center gap-4 flex-wrap">
                  <motion.div 
                    whileHover={{ scale: 1.05 }}
                    className={`px-6 py-3 rounded-xl border-2 ${
                      project.securityLevel === 'Kernel' 
                        ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400' 
                        : project.securityLevel === 'High'
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400'
                        : 'bg-yellow-500/10 border-yellow-500/40 text-yellow-400'
                    }`}
                  >
                    <span className="font-mono text-sm font-bold">
                      SECURITY LEVEL: {project.securityLevel.toUpperCase()}
                    </span>
                  </motion.div>
                  
                  {project.securityLevel === 'Kernel' && (
                    <motion.div 
                      animate={{ scale: [1, 1.05, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                      className="flex items-center gap-2 text-emerald-400 font-mono text-xs bg-emerald-500/10 px-4 py-2 rounded-xl border-2 border-emerald-500/40"
                    >
                      <Zap size={18} className="animate-pulse" />
                      <span>KERNEL-LEVEL PROTECTION ACTIVE</span>
                    </motion.div>
                  )}
                  
                  {project.category && (
                    <div className="px-4 py-2 bg-purple-500/10 border-2 border-purple-500/40 rounded-xl text-purple-400 font-mono text-xs">
                      {project.category.toUpperCase()}
                    </div>
                  )}
                </div>
                
                {/* Stats */}
                {(project.stars || project.downloads) && (
                  <div className="grid grid-cols-2 gap-4">
                    {project.stars && (
                      <div className="p-4 bg-yellow-500/5 border-2 border-yellow-500/30 rounded-xl flex items-center gap-3">
                        <Trophy className="text-yellow-400" size={24} />
                        <div>
                          <div className="text-2xl font-bold text-white">{project.stars}</div>
                          <div className="text-xs text-gray-400 font-mono">GitHub Stars</div>
                        </div>
                      </div>
                    )}
                    {project.downloads && (
                      <div className="p-4 bg-green-500/5 border-2 border-green-500/30 rounded-xl flex items-center gap-3">
                        <Rocket className="text-green-400" size={24} />
                        <div>
                          <div className="text-2xl font-bold text-white">{project.downloads.toLocaleString()}</div>
                          <div className="text-xs text-gray-400 font-mono">Downloads</div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
                
                {/* Description */}
                <div className="p-6 bg-zinc-900/60 border-2 border-zinc-800 rounded-xl">
                  <h3 className="text-sm font-mono text-cyan-400 mb-3 uppercase tracking-wider flex items-center gap-2">
                    <Code2 size={16} />
                    Project Overview
                  </h3>
                  <p className="text-gray-300 leading-relaxed">{project.description}</p>
                </div>
                
                {/* Tech Stack */}
                <div className="p-6 bg-zinc-900/60 border-2 border-zinc-800 rounded-xl">
                  <h3 className="text-sm font-mono text-cyan-400 mb-4 uppercase tracking-wider flex items-center gap-2">
                    <Code2 size={16} />
                    Technology Stack
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {project.tech.map((t: string, i: number) => (
                      <motion.span 
                        key={t}
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: i * 0.05 }}
                        whileHover={{ scale: 1.1, y: -2 }}
                        className="px-4 py-2 bg-zinc-800 text-cyan-400 border-2 border-cyan-500/40 rounded-lg font-mono text-sm hover:bg-cyan-500/10 hover:border-cyan-500/60 transition-all cursor-default"
                      >
                        {t}
                      </motion.span>
                    ))}
                  </div>
                </div>
                
                {/* Audit Details */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <motion.div 
                    whileHover={{ y: -5, boxShadow: "0 10px 40px rgba(168, 85, 247, 0.3)" }}
                    className="p-6 bg-zinc-900/60 border-2 border-zinc-800 rounded-xl hover:border-purple-500/40 transition-all"
                  >
                    <div className="flex items-center gap-2 mb-3">
                      <Lock className="text-purple-500" size={20} />
                      <h4 className="text-xs font-mono text-gray-400 uppercase">Encryption</h4>
                    </div>
                    <p className="text-white font-mono text-sm">{project.audit.encryption}</p>
                  </motion.div>
                  
                  <motion.div 
                    whileHover={{ y: -5, boxShadow: "0 10px 40px rgba(16, 185, 129, 0.3)" }}
                    className="p-6 bg-zinc-900/60 border-2 border-zinc-800 rounded-xl hover:border-green-500/40 transition-all"
                  >
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="text-green-500" size={20} />
                      <h4 className="text-xs font-mono text-gray-400 uppercase">Compliance</h4>
                    </div>
                    <p className="text-white font-mono text-sm">{project.audit.compliance}</p>
                  </motion.div>
                  
                  <motion.div 
                    whileHover={{ y: -5, boxShadow: "0 10px 40px rgba(239, 68, 68, 0.3)" }}
                    className="p-6 bg-zinc-900/60 border-2 border-zinc-800 rounded-xl hover:border-red-500/40 transition-all"
                  >
                    <div className="flex items-center gap-2 mb-3">
                      <AlertTriangle className="text-red-500" size={20} />
                      <h4 className="text-xs font-mono text-gray-400 uppercase">Threats Mitigated</h4>
                    </div>
                    <p className="text-white font-mono text-sm">{project.audit.threats}</p>
                  </motion.div>
                </div>
                
                {/* Case Study */}
                {project.caseStudy && (
                  <motion.div 
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-6 bg-linear-to-br from-cyan-500/5 to-purple-500/5 border-2 border-cyan-500/30 rounded-xl"
                  >
                    <h3 className="text-sm font-mono text-cyan-400 mb-4 uppercase tracking-wider flex items-center gap-2">
                      <Search size={18} />
                      Technical Deep Dive
                    </h3>
                    <div className="space-y-4">
                      <div className="p-4 bg-yellow-500/5 border-l-4 border-yellow-500 rounded">
                        <h4 className="text-xs font-mono text-yellow-400 mb-2 uppercase font-bold">⚡ Challenge</h4>
                        <p className="text-gray-300 text-sm leading-relaxed">{project.caseStudy.challenge}</p>
                      </div>
                      <div className="p-4 bg-green-500/5 border-l-4 border-green-500 rounded">
                        <h4 className="text-xs font-mono text-green-400 mb-2 uppercase font-bold">💡 Solution</h4>
                        <p className="text-gray-300 text-sm leading-relaxed">{project.caseStudy.solution}</p>
                      </div>
                      <div className="p-4 bg-cyan-500/5 border-l-4 border-cyan-500 rounded">
                        <h4 className="text-xs font-mono text-cyan-400 mb-2 uppercase font-bold">🎯 Result</h4>
                        <p className="text-gray-300 text-sm leading-relaxed">{project.caseStudy.result}</p>
                      </div>
                    </div>
                  </motion.div>
                )}
                
                {/* Repository Link */}
                {project.link && (
                  <motion.a
                    href={project.link}
                    target="_blank"
                    rel="noreferrer"
                    whileHover={{ scale: 1.02, boxShadow: "0 0 40px rgba(6, 182, 212, 0.4)" }}
                    whileTap={{ scale: 0.98 }}
                    className="block w-full p-5 bg-linear-to-r from-cyan-500/10 to-purple-500/10 hover:from-cyan-500/20 hover:to-purple-500/20 border-2 border-cyan-500/40 rounded-xl transition-all group text-center"
                  >
                    <div className="flex items-center justify-center gap-3 text-cyan-400 font-mono text-sm font-bold">
                      <ExternalLink size={20} />
                      <span>VIEW PROJECT REPOSITORY ON GITHUB</span>
                      <motion.div
                        animate={{ x: [0, 5, 0] }}
                        transition={{ duration: 1.5, repeat: Infinity }}
                      >
                        <ExternalLink size={20} />
                      </motion.div>
                    </div>
                  </motion.a>
                )}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    )}
  </AnimatePresence>
);

// ==================== KERNEL PULSE EFFECT ====================
const KernelPulse = () => (
  <div className="absolute inset-0 overflow-hidden rounded-r-2xl opacity-30 pointer-events-none">
    <motion.div
      className="absolute inset-0 bg-linear-to-r from-transparent via-emerald-500/40 to-transparent"
      animate={{ x: ['-100%', '200%'] }}
      transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
    />
  </div>
);

// ==================== MAIN APP ====================
const App = () => {
  const [bootComplete, setBootComplete] = useState(false);
  const [isRoot, setIsRoot] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const { scrollYProgress } = useScroll();
  const opacity = useTransform(scrollYProgress, [0, 0.2], [1, 0]);
  
  const startScan = useCallback(() => {
    setIsScanning(true);
    setScanProgress(0);
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= STATIC_PROJECTS.length) {
          clearInterval(interval);
          setIsScanning(false);
          return STATIC_PROJECTS.length;
        }
        return prev + 1;
      });
    }, 180);
  }, []);

  // Auto-scan on boot so counter always shows all 11 projects immediately
  const handleBootComplete = useCallback(() => {
    setBootComplete(true);
    setTimeout(() => startScan(), 800);
  }, [startScan]);
  
  if (!bootComplete) {
    return <KaliBootLoader onComplete={handleBootComplete} />;
  }
  
  return (
    <div className="min-h-screen bg-black text-white relative overflow-x-hidden">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@700;900&display=swap');
        * { font-family: 'JetBrains Mono', monospace; }
        h1, h2, h3, h4 { font-family: 'Orbitron', sans-serif; }
        
        @keyframes glitch-1 {
          0%, 100% { clip-path: inset(0 0 0 0); transform: translateX(0); }
          20% { clip-path: inset(20% 0 60% 0); transform: translateX(-2px); }
          40% { clip-path: inset(60% 0 20% 0); transform: translateX(2px); }
        }
        
        @keyframes glitch-2 {
          0%, 100% { clip-path: inset(0 0 0 0); transform: translateX(0); }
          20% { clip-path: inset(60% 0 20% 0); transform: translateX(2px); }
          40% { clip-path: inset(20% 0 60% 0); transform: translateX(-2px); }
        }
        
        .animate-glitch-1 { animation: glitch-1 0.5s infinite; }
        .animate-glitch-2 { animation: glitch-2 0.5s infinite; }
        
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.1); }
        ::-webkit-scrollbar-thumb { background: rgba(6, 182, 212, 0.3); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(6, 182, 212, 0.5); }
      `}</style>
      
      <EnhancedMatrixRain />
      <ParticleNetwork />

      {/* ==================== STICKY NAV ==================== */}
      <motion.nav
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="sticky top-0 z-40 w-full bg-black/80 backdrop-blur-xl border-b border-cyan-500/20 shadow-lg shadow-black/50"
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-3">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
              >
                <Shield size={18} className="text-cyan-400" />
              </motion.div>
              <span className="font-mono text-xs text-cyan-400 font-bold tracking-widest">ADNAN OS v4.3.0</span>
              <motion.div
                animate={{ opacity: [1, 0.5, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
                className="flex items-center gap-1.5"
              >
                <div className="w-1.5 h-1.5 bg-green-500 rounded-full" />
                <span className="text-[9px] font-mono text-green-400">ONLINE</span>
              </motion.div>
            </div>
            <div className="hidden md:flex items-center gap-6 text-[10px] font-mono text-gray-500 uppercase tracking-widest">
              {['System', 'Threat_Intel', 'Certifications', 'Skills', 'Projects'].map((item) => (
                <motion.button
                  key={item}
                  whileHover={{ color: '#06b6d4', y: -1 }}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                  onClick={() => {
                    const el = document.getElementById(item.toLowerCase().replace('_', '-'));
                    if (el) el.scrollIntoView({ behavior: 'smooth' });
                  }}
                >
                  {item.replace('_', ' ')}
                </motion.button>
              ))}
            </div>
            <div className="flex items-center gap-3 text-[9px] font-mono text-gray-600">
              <span className="hidden sm:block">EDR: <span className="text-emerald-400">TARTARUS ACTIVE</span></span>
              <span className="hidden lg:block">| KERNEL: <span className="text-cyan-400">6.12.0-ebpf</span></span>
            </div>
          </div>
        </div>
      </motion.nav>
      
      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        {/* Hero Section */}
        <motion.header 
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="mb-32 relative"
        >
          <motion.div style={{ opacity }} className="absolute -top-20 -left-20 w-150 h-150 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
          <motion.div style={{ opacity }} className="absolute -top-20 -right-20 w-150 h-150 bg-green-500/10 rounded-full blur-3xl pointer-events-none" />
          
          <div className="flex items-center gap-4 mb-8">
            <motion.div 
              className="p-4 bg-cyan-500/10 border-2 border-cyan-500/40 rounded-xl"
              animate={{ 
                boxShadow: ['0 0 20px rgba(6, 182, 212, 0.3)', '0 0 50px rgba(6, 182, 212, 0.6)', '0 0 20px rgba(6, 182, 212, 0.3)'],
                borderColor: ['rgba(6, 182, 212, 0.4)', 'rgba(6, 182, 212, 0.7)', 'rgba(6, 182, 212, 0.4)']
              }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              <Terminal className="text-cyan-400" size={36} />
            </motion.div>
            <div className="font-mono text-xs text-cyan-400 flex items-center gap-3">
              <Fingerprint size={16} />
              <span>ID: ADNAN_SYUKUR</span>
              <span className="text-gray-600">|</span>
              <motion.div className="flex items-center gap-2" animate={{ opacity: [1, 0.6, 1] }} transition={{ duration: 2.5, repeat: Infinity }}>
                <div className="w-2 h-2 bg-green-500 rounded-full" />
                <span className="text-green-400 font-bold">STATUS: ONLINE</span>
              </motion.div>
              <span className="text-gray-600">|</span>
              <span className="text-purple-400">UPTIME: 327d 14h</span>
            </div>
          </div>
          
          <h1 className="text-8xl md:text-9xl font-black mb-6 leading-none">
            <GlitchText className="bg-linear-to-r from-cyan-400 via-green-400 to-emerald-400 bg-clip-text text-transparent">
              ADNAN OS
            </GlitchText>
          </h1>
          
          <div className="flex items-center gap-4 mb-6">
            <motion.div 
              className="h-0.75 w-40 bg-linear-to-r from-cyan-500 via-green-500 to-transparent rounded-full"
              initial={{ width: 0 }}
              animate={{ width: 160 }}
              transition={{ duration: 1.2, delay: 0.5 }}
            />
            <p className="font-mono text-sm text-cyan-400 uppercase tracking-[0.35em]">
              Kali Linux-Inspired Security Operating System
            </p>
          </div>
          
          <p className="text-2xl max-w-4xl leading-relaxed text-gray-300 mb-8">
            Welcome to <span className="text-white font-bold">ADNAN OS</span> - A cutting-edge, 
            <span className="text-cyan-400 font-bold"> Kali-inspired security portfolio</span> showcasing 
            <span className="text-green-400 font-bold"> kernel-level expertise</span>, 
            <span className="text-purple-400 font-bold"> full-stack mastery</span>, and 
            <span className="text-yellow-400 font-bold"> penetration testing excellence</span>. 
            Created by <span className="text-white font-bold">Adnan Syukur</span>, BNSP Rank 1 Security Specialist — 
            builder of <span className="text-emerald-400 font-bold">Tartarus EDR</span>, the kernel-native shield that enforces zero-leak policy from Ring 0.
          </p>
          
{/* ==================== ACTION SECTOR ==================== */}
<div className="flex flex-wrap gap-4 mt-12">
  {/* GitHub Link */}
  <motion.a
    href="https://github.com/SS7ZX"
    target="_blank"
    rel="noreferrer"
    whileHover={{ 
      scale: 1.05, 
      boxShadow: '0 0 40px rgba(6, 182, 212, 0.6)',
      y: -5 
    }}
    whileTap={{ scale: 0.95 }}
    className="px-8 py-4 bg-linear-to-r from-cyan-600 to-emerald-600 rounded-xl font-bold text-white shadow-lg shadow-cyan-500/20 flex items-center gap-3 border border-white/10 group"
  >
    <Code2 size={22} className="group-hover:rotate-12 transition-transform" />
    <span className="tracking-tight">ACCESS_SOURCE_CODE</span>
    <ExternalLink size={18} className="opacity-50" />
  </motion.a>

  {/* Resume Download */}
  <motion.button
    onClick={() => {
  const btn = document.getElementById('download-btn-text');
  if (btn) btn.innerText = "INITIALIZING_SECURE_TRANSFER...";
  
  setTimeout(() => {
    if (btn) btn.innerText = "DECRYPTING_RESUME.DAT...";
    
    setTimeout(() => {
      const link = document.createElement('a');
      
      // 1. The 'href' is relative to the public folder (root /)
      link.href = '/CV_ADNAN_SYUKUR_2026.pdf'; 
      
      // 2. The 'download' attribute is the filename given to the user
      link.download = 'CV_ADNAN_SYUKUR_2026.pdf'; 
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      if (btn) btn.innerText = "TRANSFER_COMPLETE ✓";
      setTimeout(() => { 
        if (btn) btn.innerText = "DOWNLOAD_RESUME"; 
      }, 3000);
    }, 1500);
  }, 1000);
}}
    whileHover={{ scale: 1.05, boxShadow: '0 0 40px rgba(16, 185, 129, 0.4)', y: -5 }}
    whileTap={{ scale: 0.95 }}
    className="px-8 py-4 bg-emerald-500/10 border-2 border-emerald-500/40 rounded-xl font-bold text-emerald-400 hover:bg-emerald-500/20 transition-all flex items-center gap-3 relative overflow-hidden group"
  >
    <motion.div 
      className="absolute inset-0 bg-emerald-500/10 pointer-events-none"
      initial={{ x: '-100%' }}
      whileHover={{ x: '100%' }}
      transition={{ duration: 0.8, repeat: Infinity, ease: "linear" }}
    />
    <Rocket size={22} className="relative z-10" />
    <span id="download-btn-text" className="relative z-10 tracking-widest text-xs">
      DOWNLOAD_RESUME
    </span>
    <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_8px_#10b981] relative z-10" />
  </motion.button>

  {/* LinkedIn */}
  <motion.a
    href="www.linkedin.com/in/adnansyukurs"
    target="_blank"
    rel="noreferrer"
    whileHover={{ scale: 1.05, boxShadow: '0 0 40px rgba(139, 92, 246, 0.4)', y: -5 }}
    whileTap={{ scale: 0.95 }}
    className="px-8 py-4 bg-purple-500/10 border-2 border-purple-500/40 rounded-xl font-bold text-purple-400 hover:bg-purple-500/20 transition-all flex items-center gap-3 group"
  >
    <Users size={22} className="group-hover:scale-110 transition-transform" />
    <span className="tracking-widest text-xs">LINKEDIN_PROFILE</span>
  </motion.a>
</div>
        </motion.header>

        {/* Tartarus EDR Featured Banner — Premium Elite */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="mb-16 relative overflow-hidden"
        >
          <div className="p-8 bg-linear-to-rbg-linear-to-r from-emerald-950/60 via-zinc-900/90 to-purple-950/60 border-2 border-emerald-500/50 rounded-2xl shadow-2xl shadow-emerald-500/20 relative overflow-hidden">
            {/* Corner accent */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-linear-to-tr from-emerald-500/20 to-transparent rounded-bl-[100px] pointer-events-none" />
            <div className="absolute bottom-0 left-0 w-24 h-24 bg-linear-to-tr from-purple-500/10 to-transparent rounded-tr-[80px] pointer-events-none" />
            {/* Animated scan line */}
            <motion.div
              className="absolute inset-0 bg-linear-to-r from-transparent via-emerald-500/8 to-transparent pointer-events-none"
              animate={{ x: ['-100%', '200%'] }}
              transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
            />
            <div className="flex flex-wrap items-start gap-8 relative z-10">
              <div className="flex items-start gap-4 flex-1 min-w-0">
                <motion.div
                  animate={{ rotate: [0, 360] }}
                  transition={{ duration: 15, repeat: Infinity, ease: 'linear' }}
                  className="p-3 bg-emerald-500/20 border-2 border-emerald-500/50 rounded-xl shrink-0"
                >
                  <Zap size={28} className="text-emerald-400" />
                </motion.div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <motion.span 
                      animate={{ opacity: [1, 0.7, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                      className="text-[10px] font-mono px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 rounded uppercase tracking-widest"
                    >⚡ NEW · Kernel-Grade</motion.span>
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 rounded uppercase tracking-widest">★ Flagship Project</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/30 rounded uppercase tracking-widest">Ring 0 · Professional Grade</span>
                  </div>
                  <h3 className="text-2xl font-black text-white mb-1">🏛️ Tartarus EDR: Omniscient Kernel Shield</h3>
                  <p className="text-sm text-emerald-400/80 font-mono">eBPF · Rust · bpf_send_signal(9) · BPF Ring Buffer · Zero-Leak · Discord Intelligence Uplink</p>
                  <p className="text-xs text-gray-500 font-mono mt-2 leading-relaxed max-w-xl">
                    Bridges Ring 0 kernel space → Rust control plane → Discord cloud relay. The only EDR that enforces a zero-descriptor-leak policy via in-kernel SIGKILL before file access is ever granted.
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-4 text-center shrink-0">
                {[
                  { val: '231', label: 'Stars', color: 'text-yellow-400' },
                  { val: '5.8K', label: 'Downloads', color: 'text-green-400' },
                  { val: 'Ring 0', label: 'Privilege', color: 'text-emerald-400' },
                  { val: '0ms', label: 'FD Leak', color: 'text-cyan-400' },
                  { val: '★★★★★', label: 'Verdict', color: 'text-yellow-300' },
                ].map((s) => (
                  <div key={s.label} className="min-w-15">
                    <div className={`text-xl font-black font-mono ${s.color}`}>{s.val}</div>
                    <div className="text-[8px] font-mono text-gray-500 uppercase">{s.label}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-6 pt-5 border-t border-emerald-500/20 grid grid-cols-1 md:grid-cols-3 gap-3 relative z-10">
              {[
                { label: '① The Infiltrator', desc: 'eBPF/C hooks openat() at Ring 0 — inspects filename memory address with in-line evaluation before any return path', color: 'text-cyan-400', border: 'border-cyan-500/30', bg: 'bg-cyan-500/5' },
                { label: '② The Enforcer', desc: 'bpf_send_signal(9) terminates the calling thread before the FD is ever returned — zero-leak guarantee at kernel level', color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/5' },
                { label: '③ The Uplink', desc: 'Rust tokio::spawn relay streams alerts as Discord Rich Embed JSON with stateful forum thread management', color: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/5' },
              ].map((item) => (
                <div key={item.label} className={`p-4 ${item.bg} rounded-xl border ${item.border}`}>
                  <div className={`text-[10px] font-mono font-bold ${item.color} uppercase mb-2`}>{item.label}</div>
                  <div className="text-[10px] text-gray-400 leading-relaxed">{item.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
        <h2 id="system" className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-12 flex items-center gap-2">
          <Gauge size={16} className="text-cyan-400" />
          System_Performance_Monitor
        </h2>
        <div className="mb-24">
          <SystemMonitor />
        </div>
        
        {/* Globe and Terminal */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-24">
          <div className="lg:col-span-2">
            <h2 className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-8 flex items-center gap-2">
              <Globe size={16} className="text-cyan-400" />
              Global_Network_Visualization
            </h2>
            <HolographicCard>
              <div className="p-6 bg-zinc-900/60 border-2 border-cyan-500/40 rounded-xl">
                <Ultra3DGlobe />
              </div>
            </HolographicCard>
          </div>
          
          <div>
            <h2 className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-8 flex items-center gap-2">
              <Terminal size={16} className="text-green-400" />
              Kali_Terminal
            </h2>
            <AdvancedTerminal 
              onRootAccess={() => setIsRoot(true)} 
              onScanTrigger={startScan} 
              isRoot={isRoot} 
            />
          </div>
        </div>
        
        {/* Threat Intelligence */}
        <h2 id="threat-intel" className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-12 flex items-center gap-2">
          <Radar size={16} className="text-red-400 animate-pulse" />
          Live_Threat_Intelligence
        </h2>
        <div className="mb-24">
          <LiveThreatFeed />
        </div>
        
        {/* Elite Stats Overview */}
        <div className="mb-24 grid grid-cols-1 md:grid-cols-4 gap-6">
          <HolographicCard className="group md:col-span-1">
            <motion.div 
              whileHover={{ scale: 1.05, y: -5 }}
              className="p-8 bg-zinc-900/60 border-2 border-cyan-500/40 rounded-2xl flex flex-col items-center justify-center hover:bg-zinc-900/80 transition-all relative overflow-hidden"
            >
              <motion.div
                className="absolute inset-0 bg-linear-to-br from-cyan-500/5 to-emerald-500/5 pointer-events-none"
                animate={{ opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 3, repeat: Infinity }}
              />
              <p className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-3 group-hover:text-cyan-400 transition-colors relative z-10">
                Projects_Deployed
              </p>
              <motion.h4 
                key={scanProgress}
                initial={{ scale: 1.3, color: '#06b6d4' }}
                animate={{ scale: 1, color: '#ffffff' }}
                transition={{ duration: 0.3 }}
                className="text-8xl font-black text-white font-mono tracking-tighter mb-2 relative z-10"
              >
                {scanProgress.toString().padStart(2, '0')}
              </motion.h4>
              <p className="text-xs font-mono text-cyan-400 relative z-10">/ {STATIC_PROJECTS.length.toString().padStart(2,'0')} Total</p>
              <div className="mt-3 flex gap-1 relative z-10">
                {STATIC_PROJECTS.map((_, i) => (
                  <motion.div
                    key={i}
                    className={`w-1.5 h-1.5 rounded-full ${i < scanProgress ? 'bg-cyan-400' : 'bg-zinc-700'}`}
                    animate={i < scanProgress ? { scale: [1, 1.4, 1] } : {}}
                    transition={{ duration: 0.3, delay: i * 0.05 }}
                  />
                ))}
              </div>
            </motion.div>
          </HolographicCard>
          
          <div className="md:col-span-3 p-8 bg-zinc-900/40 border-2 border-cyan-500/40 rounded-2xl flex flex-col justify-center space-y-5">
            <div className="flex justify-between items-center text-[10px] font-mono uppercase tracking-widest">
              <span className="flex items-center gap-2">
                <Activity size={14} className="text-cyan-400 animate-pulse"/>
                System_Security_Status
              </span>
              <span className="text-cyan-400 bg-cyan-500/10 px-4 py-2 rounded-full border-2 border-cyan-500/40">
                {isScanning ? '⚡ Scanning Projects...' : `✓ All ${STATIC_PROJECTS.length} Systems Verified`}
              </span>
            </div>
            
            <div className="h-5 bg-zinc-900 rounded-full overflow-hidden border-2 border-cyan-500/40 shadow-inner">
              <motion.div 
                animate={{ width: `${(scanProgress / STATIC_PROJECTS.length) * 100}%` }}
                className="h-full bg-linear-to-r from-cyan-500 via-green-500 to-emerald-500 relative"
                transition={{ duration: 0.3, ease: "easeOut" }}
              >
                <motion.div
                  className="absolute inset-0 bg-linear-to-r from-transparent via-white to-transparent opacity-40"
                  animate={{ x: ['-100%', '200%'] }}
                  transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                />
              </motion.div>
            </div>

            {/* Elite additional stats row */}
            <div className="grid grid-cols-4 gap-3 pt-2">
              {[
                { label: 'Kernel EDRs', value: '3', color: 'emerald', icon: '🛡️' },
                { label: 'Total Stars', value: '2', color: 'yellow', icon: '⭐' },
                { label: 'Vuln. Found', value: '0', color: 'green', icon: '✓' },
              ].map((stat) => (
                <div key={stat.label} className={`text-center p-3 bg-${stat.color}-500/5 border border-${stat.color}-500/20 rounded-xl`}>
                  <div className="text-lg mb-1">{stat.icon}</div>
                  <div className={`text-lg font-black font-mono text-${stat.color}-400`}>{stat.value}</div>
                  <div className="text-[8px] font-mono text-gray-500 uppercase">{stat.label}</div>
                </div>
              ))}
            </div>
            
            <div className="flex justify-between items-center text-[10px] font-mono text-gray-500 uppercase">
              <span className="flex items-center gap-2">
                <Shield size={13} className="text-green-400" />
                0% Critical Vulnerabilities
              </span>
              <span className="text-green-400 font-bold flex items-center gap-2">
                100% Secure System
                <Zap size={13} />
              </span>
            </div>
          </div>
        </div>
        
        {/* Certifications */}
        <h2 id="certifications" className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-12 flex items-center gap-2">
          <Award size={16} className="text-yellow-400" />
          Professional_Certifications
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-32">
          {[
            { icon: Award, title: 'BNSP RANK 1', desc: 'Network Engineering', color: 'cyan', gradient: 'from-cyan-500/10 to-blue-500/10', border: 'border-cyan-500/40' },
            { icon: Database, title: 'DB DEVELOPER', desc: 'Database Professional', color: 'yellow', gradient: 'from-yellow-500/10 to-orange-500/10', border: 'border-yellow-500/40' },
            { icon: Shield, title: 'VAPT EXCELLENCE', desc: 'Security Evaluation', color: 'red', gradient: 'from-red-500/10 to-orange-500/10', border: 'border-red-500/40' }
          ].map((cert, i) => {
            const Icon = cert.icon;
            return (
              <HolographicCard key={i} className="group">
                <motion.div 
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.15 }}
                  whileHover={{ y: -8, scale: 1.02 }}
                  className={`p-8 bg-linear-to-br ${cert.gradient} border-2 ${cert.border} rounded-2xl flex items-start gap-4 hover:border-${cert.color}-500/60 transition-all shadow-lg hover:shadow-${cert.color}-500/30`}
                >
                  <Icon className={`text-${cert.color}-400 shrink-0 group-hover:scale-110 group-hover:rotate-12 transition-all duration-300`} size={44} />
                  <div>
                    <h3 className="text-white font-bold uppercase text-2xl mb-2">
                      <GlitchText>{cert.title}</GlitchText>
                    </h3>
                    <p className={`text-sm text-${cert.color}-400 font-mono mb-2`}>{cert.desc}</p>
                    <p className="text-xs text-gray-400">Certified Professional - Excellence</p>
                  </div>
                </motion.div>
              </HolographicCard>
            );
          })}
        </div>
        
        {/* Leadership */}
        <h2 className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-12 flex items-center gap-2">
          <Users size={16} className="text-purple-400" />
          Leadership_Experience
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-32">
          {STATIC_EXPERIENCES.map((exp, i) => (
            <HolographicCard key={exp._id} className="group">
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.12 }}
                whileHover={{ scale: 1.02, y: -5 }}
                className="p-8 bg-zinc-900/40 border-2 border-purple-500/40 rounded-2xl hover:bg-zinc-900/60 hover:border-purple-500/60 transition-all"
              >
                {exp.title.toLowerCase().includes('basket') ? (
                  <Trophy className="text-orange-400 mb-4 group-hover:scale-110 transition-transform" size={40} />
                ) : (
                  <Users className="text-purple-400 mb-4 group-hover:scale-110 transition-transform" size={40} />
                )}
                <h3 className="text-2xl font-bold text-white mb-2 group-hover:text-purple-400 transition-colors">
                  {exp.title}
                </h3>
                <p className="text-purple-400 text-sm font-mono mb-1">{exp.organization}</p>
                {exp.period && <p className="text-gray-500 text-xs font-mono mb-4">{exp.period}</p>}
                <p className="text-sm text-gray-400 leading-relaxed mb-4">{exp.description}</p>
                {exp.achievements && exp.achievements.length > 0 && (
                  <div className="space-y-1 mt-4 pt-4 border-t border-purple-500/20">
                    {exp.achievements.map((achievement, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-xs text-gray-400">
                        <Check size={14} className="text-green-400 shrink-0 mt-0.5" />
                        <span>{achievement}</span>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            </HolographicCard>
          ))}
        </div>
        
        {/* ==================== SKILLS ARSENAL ==================== */}
        <h2 id="skills" className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-12 flex items-center gap-2">
          <Zap size={16} className="text-yellow-400" />
          Skills_Arsenal
        </h2>
        <div className="mb-32">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                domain: 'Kernel & Systems',
                icon: '⚙️',
                color: 'emerald',
                borderColor: 'border-emerald-500/40',
                bgColor: 'from-emerald-500/10 to-zinc-900',
                skills: [
                  { name: 'C / eBPF', level: 95 },
                  { name: 'Rust (Systems)', level: 88 },
                  { name: 'Linux Kernel (LKM)', level: 92 },
                  { name: 'x86_64 Assembly', level: 72 },
                  { name: 'BPF Ring Buffer', level: 90 },
                ]
              },
              {
                domain: 'Security Engineering',
                icon: '🛡️',
                color: 'cyan',
                borderColor: 'border-cyan-500/40',
                bgColor: 'from-cyan-500/10 to-zinc-900',
                skills: [
                  { name: 'Penetration Testing', level: 93 },
                  { name: 'VAPT / OWASP', level: 95 },
                  { name: 'Memory Forensics', level: 85 },
                  { name: 'Reverse Engineering', level: 80 },
                  { name: 'Exploit Development', level: 78 },
                ]
              },
              {
                domain: 'Full-Stack & Cloud',
                icon: '🚀',
                color: 'purple',
                borderColor: 'border-purple-500/40',
                bgColor: 'from-purple-500/10 to-zinc-900',
                skills: [
                  { name: 'React / TypeScript', level: 92 },
                  { name: 'Node.js / Express', level: 90 },
                  { name: 'Firebase / Cloud', level: 88 },
                  { name: 'Docker / DevOps', level: 82 },
                  { name: 'Python / ML/NLP', level: 85 },
                ]
              }
            ].map((category, ci) => (
              <HolographicCard key={ci} className="group">
                <motion.div
                  initial={{ opacity: 0, y: 30 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: ci * 0.15 }}
                  className={`p-8 bg-linear-to-b ${category.bgColor} border-2 ${category.borderColor} rounded-2xl hover:border-${category.color}-500/70 transition-all`}
                >
                  <div className="flex items-center gap-3 mb-6">
                    <span className="text-3xl">{category.icon}</span>
                    <h3 className={`text-base font-bold text-${category.color}-400 font-mono uppercase`}>{category.domain}</h3>
                  </div>
                  <div className="space-y-4">
                    {category.skills.map((skill, si) => (
                      <div key={si}>
                        <div className="flex justify-between items-center mb-1.5">
                          <span className="text-xs font-mono text-gray-300">{skill.name}</span>
                          <span className={`text-xs font-mono text-${category.color}-400 font-bold`}>{skill.level}%</span>
                        </div>
                        <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden border border-zinc-700">
                          <motion.div
                            className={`h-full bg-linear-to-r from-${category.color}-600 to-${category.color}-400 rounded-full`}
                            initial={{ width: 0 }}
                            animate={{ width: `${skill.level}%` }}
                            transition={{ duration: 1.2, delay: ci * 0.15 + si * 0.1, ease: 'easeOut' }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              </HolographicCard>
            ))}
          </div>
          
          {/* Tech Badge Cloud */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="mt-8 p-6 bg-zinc-900/40 border-2 border-zinc-800 rounded-2xl"
          >
            <p className="text-[9px] font-mono text-gray-600 uppercase tracking-widest mb-4">Full Technology Stack</p>
            <div className="flex flex-wrap gap-2">
              {['C', 'eBPF', 'Rust', 'Python', 'Node.js', 'React', 'TypeScript', 'Linux Kernel', 'Docker', 'Firebase', 'MongoDB', 'Redis', 'Figma', 'Burp Suite', 'Nmap', 'Metasploit', 'Wireshark', 'LSM Hooks', 'BPF Ring Buffer', 'tokio', 'OWASP', 'x86_64 ASM', 'Kprobes', 'SELinux', 'nftables', 'Git', 'Google Cloud', 'Tailwind CSS', 'JWT', 'OAuth2'].map((tech, i) => (
                <motion.span
                  key={tech}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.5 + i * 0.03 }}
                  whileHover={{ scale: 1.1, y: -2 }}
                  className="text-[10px] font-mono px-3 py-1.5 bg-zinc-800 text-gray-400 border border-zinc-700 rounded-lg hover:border-cyan-500/40 hover:text-cyan-400 hover:bg-cyan-500/5 transition-all cursor-default"
                >
                  {tech}
                </motion.span>
              ))}
            </div>
          </motion.div>
        </div>

        {/* Projects */}
        <h2 id="projects" className="text-sm font-mono text-gray-500 uppercase tracking-[0.4em] mb-12 flex justify-between items-center">
          <span className="flex items-center gap-2">
            <Rocket size={16} className="text-cyan-400" />
            Project_Portfolio
          </span>
          {isScanning && (
            <motion.span 
              animate={{ opacity: [1, 0.5, 1] }}
              transition={{ duration: 1.2, repeat: Infinity }}
              className="text-cyan-400 tracking-widest flex items-center gap-3 bg-cyan-500/10 px-5 py-2 rounded-xl border-2 border-cyan-500/40 text-sm"
            >
              <Activity size={16} />
              <span>Scanning Projects...</span>
            </motion.span>
          )}
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-32">
          {STATIC_PROJECTS.map((project, index) => (
            <HolographicCard key={project._id} className="group">
              <motion.div 
                onClick={() => setSelectedProject(project)}
                initial={{ opacity: 0.1, y: 20 }}
                whileHover={{ y: -10, scale: 1.02 }}
                animate={{ 
                  opacity: index < scanProgress ? 1 : 0.1, 
                  y: index < scanProgress ? 0 : 20,
                }}
                transition={{ duration: 0.4, type: "spring", stiffness: 100 }}
                className="p-8 bg-zinc-900/50 border-2 border-l-4 border-cyan-500/40 rounded-r-2xl cursor-pointer relative overflow-hidden hover:border-cyan-500/70 hover:bg-zinc-900/70 transition-all shadow-lg hover:shadow-cyan-500/30"
                style={{
                  borderLeftColor: index < scanProgress 
                    ? (project.securityLevel === 'Kernel' ? '#10b981' : '#06b6d4') 
                    : 'transparent'
                }}
              >
                {project.securityLevel === 'Kernel' && <KernelPulse />}
                
                {/* Flagship badge for Tartarus */}
                {project._id === 'p11' && (
                  <div className="absolute top-3 right-3 z-20">
                    <motion.div
                      animate={{ opacity: [1, 0.7, 1] }}
                      transition={{ duration: 1.5, repeat: Infinity }}
                      className="text-[9px] font-mono px-2 py-0.5 bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 rounded uppercase tracking-widest"
                    >
                      ★ Flagship
                    </motion.div>
                  </div>
                )}
                
                <div className="flex justify-between items-start mb-5 relative z-10">
                  <div className="flex items-center gap-3 flex-1">
                    <h3 className="text-2xl font-bold text-white group-hover:text-cyan-400 transition-colors">
                      {project.title}
                    </h3>
                    {project.link && (
                      <a 
                        href={project.link} 
                        target="_blank" 
                        rel="noreferrer" 
                        onClick={(e) => e.stopPropagation()}
                        className="opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <motion.div whileHover={{ scale: 1.3, rotate: 45 }} whileTap={{ scale: 0.9 }}>
                          <ExternalLink size={18} className="text-cyan-400 hover:text-cyan-300" />
                        </motion.div>
                      </a>
                    )}
                  </div>
                  
                  {project.securityLevel === 'Kernel' ? (
                    <motion.div animate={{ rotate: [0, 360] }} transition={{ duration: 20, repeat: Infinity, ease: "linear" }}>
                      <Zap size={24} className="text-emerald-400" />
                    </motion.div>
                  ) : (
                    <Code2 size={24} className="text-gray-700 group-hover:text-cyan-400 transition-colors" />
                  )}
                </div>
                
                <p className="text-gray-400 mb-6 text-sm relative z-10 line-clamp-2 group-hover:text-gray-300 transition-colors leading-relaxed">
                  {project.description}
                </p>
                
                {project.category && (
                  <div className="mb-4">
                    <span className="text-[10px] font-mono px-3 py-1 bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded-lg uppercase">
                      {project.category}
                    </span>
                  </div>
                )}
                
                <div className="flex flex-wrap gap-2 relative z-10 mb-5">
                  {project.tech.slice(0, 4).map((t, i) => (
                    <motion.span 
                      key={t}
                      initial={{ opacity: 0, scale: 0 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: index * 0.1 + i * 0.06 }}
                      className="text-[10px] font-mono px-3 py-1.5 bg-zinc-800 text-cyan-400/80 border border-cyan-500/30 rounded-lg uppercase hover:bg-cyan-500/10 hover:border-cyan-500/60 transition-all"
                    >
                      {t}
                    </motion.span>
                  ))}
                  {project.tech.length > 4 && (
                    <span className="text-[10px] font-mono px-3 py-1.5 bg-zinc-800 text-gray-500 border border-zinc-700 rounded-lg">
                      +{project.tech.length - 4} more
                    </span>
                  )}
                </div>
                
                {(project.stars || project.downloads) && (
                  <div className="flex items-center gap-4 mb-4 text-xs font-mono">
                    {project.stars && (
                      <div className="flex items-center gap-1 text-yellow-400">
                        <Trophy size={12} className="fill-yellow-400" />
                        <span>{project.stars}</span>
                      </div>
                    )}
                    {project.downloads && project.downloads > 0 && (
                      <div className="flex items-center gap-1 text-green-400">
                        <Rocket size={12} />
                        <span>{project.downloads.toLocaleString()}</span>
                      </div>
                    )}
                  </div>
                )}
                
                <div className="text-[9px] font-mono text-gray-500 uppercase flex items-center gap-2 pt-4 border-t border-zinc-800/50 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Search size={12} className="text-cyan-400" />
                  <span>Click_for_Comprehensive_Security_Audit</span>
                </div>
              </motion.div>
            </HolographicCard>
          ))}
        </div>
        
        {/* ==================== CONTACT / CTA ====================== */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="mb-24 relative overflow-hidden"
        >
          <div className="p-12 bg-linear-to-br from-cyan-500/10 via-zinc-900/80 to-emerald-500/10 border-2 border-cyan-500/40 rounded-2xl shadow-2xl shadow-cyan-500/10 relative overflow-hidden">
            <motion.div
              className="absolute inset-0 bg-linear-to-r from-transparent via-cyan-500/5 to-transparent pointer-events-none"
              animate={{ x: ['-100%', '200%'] }}
              transition={{ duration: 6, repeat: Infinity, ease: 'linear' }}
            />
            <div className="relative z-10 text-center">
              <motion.div
                animate={{ rotate: [0, 360] }}
                transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
                className="inline-block mb-6"
              >
                <div className="p-4 bg-cyan-500/10 border-2 border-cyan-500/40 rounded-2xl">
                  <Radar size={40} className="text-cyan-400" />
                </div>
              </motion.div>
              <h2 className="text-4xl md:text-5xl font-black text-white mb-4">
                <GlitchText>OPEN_TO_CONNECT</GlitchText>
              </h2>
              <p className="text-gray-400 text-lg max-w-2xl mx-auto mb-8 font-mono leading-relaxed">
                Whether you need a <span className="text-cyan-400">kernel security engineer</span>, a <span className="text-emerald-400">full-stack architect</span>, or someone who can operate at both Ring 0 and the cloud layer — let's talk.
              </p>
              <div className="flex flex-wrap gap-4 justify-center">
                <motion.a
                  href="https://wa.me/6289601121014?text=Hi%20Adnan%2C%20I%27m%20interested%20in%20connecting%20with%20you%20regarding%20potential%20opportunities."
                  whileHover={{ scale: 1.05, boxShadow: '0 0 50px rgba(6, 182, 212, 0.5)', y: -5 }}
                  whileTap={{ scale: 0.95 }}
                  className="px-10 py-5 bg-linear-to-r from-cyan-600 to-emerald-600 rounded-2xl font-black text-white text-lg shadow-2xl shadow-cyan-500/20 flex items-center gap-3 border border-white/10"
                >
                  <Zap size={24} />
                  INITIATE_CONTACT
                </motion.a>
                <motion.a
                  href="https://github.com/SS7ZX"
                  target="_blank"
                  rel="noreferrer"
                  whileHover={{ scale: 1.05, y: -5 }}
                  whileTap={{ scale: 0.95 }}
                  className="px-10 py-5 bg-zinc-900 border-2 border-zinc-700 hover:border-cyan-500/60 rounded-2xl font-black text-gray-300 hover:text-white text-lg flex items-center gap-3 transition-all"
                >
                  <Code2 size={24} />
                  VIEW_GITHUB
                </motion.a>
              </div>
              <div className="mt-10 flex flex-wrap justify-center gap-8 text-xs font-mono text-gray-500">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  <span>AVAILABLE FOR OPPORTUNITIES</span>
                </div>
                <div className="flex items-center gap-2">
                  <Globe size={12} className="text-cyan-400" />
                  <span>DEPOK, INDONESIA · REMOTE OK</span>
                </div>
                <div className="flex items-center gap-2">
                  <Shield size={12} className="text-emerald-400" />
                  <span>SECURITY CLEARANCE READY</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Footer */}
        <footer className="mt-48 pt-10 border-t-2 border-zinc-900 flex flex-col md:flex-row justify-between items-center gap-8 text-[10px] font-mono uppercase text-gray-600">
          <div className="flex items-center flex-wrap gap-6">
            <div className="flex items-center gap-2">
              <motion.span 
                animate={{ scale: [1, 1.3, 1], opacity: [1, 0.7, 1] }}
                transition={{ duration: 2.5, repeat: Infinity }}
                className={`w-2.5 h-2.5 rounded-full ${isRoot ? 'bg-emerald-500 shadow-[0_0_12px_#10b981]' : 'bg-cyan-500 shadow-[0_0_12px_#06b6d4]'}`}
              /> 
              {isRoot ? 'AUTH: ROOT_ACCESS_GRANTED' : 'AUTH: GUEST_MODE'}
            </div>
            
            <div className="flex items-center gap-2 border-l border-zinc-800 pl-6">
              <Wifi size={13} className="text-emerald-400" />
              <span>NETWORK: <span className="text-emerald-400">CONNECTED</span></span>
            </div>
            
            <div className="hidden md:flex items-center gap-2 border-l border-zinc-800 pl-6">
              <Globe size={13} className="text-cyan-400" />
              <span>LOCATION: <span className="text-white">DEPOK, INDONESIA</span></span>
            </div>
            
            <div className="hidden lg:flex items-center gap-2 border-l border-zinc-800 pl-6">
              <Shield size={13} className="text-green-400" />
              <span>SECURITY: <span className="text-green-400">MAXIMUM</span></span>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <p className="text-center">
              <GlitchText>© 2026 ADNAN SYUKUR // ADNAN OS v4.3.0-TARTARUS</GlitchText>
            </p>
          </div>
        </footer>
      </main>
      
      {/* Modals */}
      <ProjectModal project={selectedProject} onClose={() => setSelectedProject(null)} />
    </div>
  );
};

export default App;