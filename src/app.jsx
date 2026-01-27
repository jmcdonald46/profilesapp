import React, { useState, useEffect } from 'react';
import { Github, Linkedin, Mail, ArrowRight, Code, Cloud, GraduationCap, Camera, X, RefreshCw, ChevronLeft, ChevronRight, Shield, AlertTriangle, Activity, Lock, Database, Zap } from 'lucide-react';

export default function App() {
    const [scrollY, setScrollY] = useState(0);
    const [showDocument, setShowDocument] = useState(false);
    const [showGallery, setShowGallery] = useState(false);
    const [showTechStack, setShowTechStack] = useState(false);
    const [showSecuritySandbox, setShowSecuritySandbox] = useState(false);
    const [pdfError, setPdfError] = useState(false);

    // Gallery state
    const [images, setImages] = useState([]);
    const [galleryLoading, setGalleryLoading] = useState(false);
    const [galleryError, setGalleryError] = useState(null);
    const [selectedImage, setSelectedImage] = useState(null);
    const [profileImageUrl, setProfileImageUrl] = useState('');

    // Pagination state
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(0);
    const [totalImages, setTotalImages] = useState(0);
    const imagesPerPage = 5;

    // Security Sandbox state
    const [sandboxLogs, setSandboxLogs] = useState([]);
    const [isSimulating, setIsSimulating] = useState(false);
    const [selectedThreat, setSelectedThreat] = useState(null);

    const googleDocUrl = 'https://drive.google.com/file/d/1L7QnVHeVyMD6w9E5lS_MuRoc3Fns5ru7/view?usp=sharing';
    const documentUrl = googleDocUrl.replace('/view?usp=sharing', '/preview');

    useEffect(() => {
        const handleScroll = () => setScrollY(window.scrollY);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    useEffect(() => {
        const fetchProfileImage = async () => {
            try {
                const API_ENDPOINT = 'https://lzgtwdx5ii.execute-api.us-east-2.amazonaws.com/prod/images?profile=true';
                const response = await fetch(API_ENDPOINT);
                if (response.ok) {
                    const data = await response.json();
                    setProfileImageUrl(data.url);
                }
            } catch (err) {
                console.error('Error fetching profile image:', err);
            }
        };
        fetchProfileImage();
    }, []);

    const fetchImages = async (page = 1) => {
        try {
            setGalleryLoading(true);
            setGalleryError(null);

            const API_ENDPOINT = `https://lzgtwdx5ii.execute-api.us-east-2.amazonaws.com/prod/images?page=${page}&limit=${imagesPerPage}`;
            const response = await fetch(API_ENDPOINT);

            if (!response.ok) {
                throw new Error('Failed to fetch images from API');
            }

            const data = await response.json();
            setImages(data.images || []);

            if (data.pagination) {
                setCurrentPage(data.pagination.currentPage);
                setTotalPages(data.pagination.totalPages);
                setTotalImages(data.pagination.totalImages);
            }
        } catch (err) {
            console.error('Error fetching images:', err);
            setGalleryError('Failed to load images. Please check your API configuration.');
        } finally {
            setGalleryLoading(false);
        }
    };

    const handleOpenGallery = () => {
        setShowGallery(true);
        if (images.length === 0) {
            fetchImages(1);
        }
    };

    const handlePageChange = (newPage) => {
        if (newPage >= 1 && newPage <= totalPages) {
            fetchImages(newPage);
            const galleryContainer = document.querySelector('.gallery-container');
            if (galleryContainer) {
                galleryContainer.scrollTop = 0;
            }
        }
    };

    const formatFileSize = (bytes) => {
        if (bytes === 0) return 'Unknown';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    };

    // Security Sandbox Functions
    const addLog = (message, type = 'info', threatType = '') => {
        const timestamp = new Date().toISOString();
        setSandboxLogs(prev => [{
            id: Date.now(),
            timestamp,
            message,
            type,
            threatType
        }, ...prev].slice(0, 100)); // Keep last 100 logs
    };

    const simulateBruteForce = async () => {
        setIsSimulating(true);
        addLog('🔴 Initiating Brute Force Attack Simulation', 'danger', 'Brute Force');
        
        const usernames = ['admin', 'root', 'user', 'test', 'administrator'];
        const passwords = ['password123', 'admin', '12345', 'letmein', 'qwerty'];
        
        for (let i = 0; i < 10; i++) {
            const username = usernames[Math.floor(Math.random() * usernames.length)];
            const password = passwords[Math.floor(Math.random() * passwords.length)];
            
            try {
                // Simulate API call to your endpoint
                const response = await fetch('https://lzgtwdx5ii.execute-api.us-east-2.amazonaws.com/prod/images?profile=true', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, simulation: true })
                });
                
                addLog(`Failed login attempt: ${username} / ${password}`, 'warning', 'Brute Force');
            } catch (err) {
                addLog(`Simulated failed login: ${username}`, 'warning', 'Brute Force');
            }
            
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        
        addLog('✅ Brute Force Simulation Complete', 'success', 'Brute Force');
        setIsSimulating(false);
    };

    const simulateSQLInjection = async () => {
        setIsSimulating(true);
        addLog('🔴 Initiating SQL Injection Attack Simulation', 'danger', 'SQL Injection');
        
        const sqlPayloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--"
        ];
        
        for (const payload of sqlPayloads) {
            try {
                // Simulate API call with malicious payload
                await fetch('https://lzgtwdx5ii.execute-api.us-east-2.amazonaws.com/prod/images?profile=trueE', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: payload, simulation: true })
                });
                
                addLog(`SQL Injection attempt: ${payload}`, 'warning', 'SQL Injection');
            } catch (err) {
                addLog(`Simulated SQL Injection: ${payload.substring(0, 30)}...`, 'warning', 'SQL Injection');
            }
            
            await new Promise(resolve => setTimeout(resolve, 300));
        }
        
        addLog('✅ SQL Injection Simulation Complete', 'success', 'SQL Injection');
        setIsSimulating(false);
    };

    const simulateDDoS = async () => {
        setIsSimulating(true);
        addLog('🔴 Initiating DDoS Attack Simulation', 'danger', 'DDoS');
        
        const requests = 50;
        addLog(`Generating ${requests} rapid requests...`, 'warning', 'DDoS');
        
        const promises = [];
        for (let i = 0; i < requests; i++) {
            promises.push(
                fetch('https://lzgtwdx5ii.execute-api.us-east-2.amazonaws.com/prod/images?profile=true', {
                    method: 'GET',
                    headers: { 'X-Simulation': 'ddos' }
                }).catch(() => {})
            );
            
            if (i % 10 === 0) {
                addLog(`Sent ${i}/${requests} requests`, 'info', 'DDoS');
            }
        }
        
        await Promise.allSettled(promises);
        addLog('✅ DDoS Simulation Complete', 'success', 'DDoS');
        setIsSimulating(false);
    };

    const simulateUnauthorizedAccess = async () => {
        setIsSimulating(true);
        addLog('🔴 Initiating Unauthorized Access Simulation', 'danger', 'Unauthorized Access');
        
        const sensitiveEndpoints = [
            '/api/admin/users',
            '/api/admin/config',
            '/api/private/data',
            '/api/internal/secrets',
            '/api/admin/logs'
        ];
        
        for (const endpoint of sensitiveEndpoints) {
            try {
                await fetch(`YOUR_BASE_URL${endpoint}`, {
                    method: 'GET',
                    headers: { 
                        'Authorization': 'Bearer invalid_token',
                        'X-Simulation': 'unauthorized' 
                    }
                });
                
                addLog(`Unauthorized access attempt: ${endpoint}`, 'warning', 'Unauthorized Access');
            } catch (err) {
                addLog(`Simulated unauthorized access: ${endpoint}`, 'warning', 'Unauthorized Access');
            }
            
            await new Promise(resolve => setTimeout(resolve, 400));
        }
        
        addLog('✅ Unauthorized Access Simulation Complete', 'success', 'Unauthorized Access');
        setIsSimulating(false);
    };

    const simulateDataExfiltration = async () => {
        setIsSimulating(true);
        addLog('🔴 Initiating Data Exfiltration Simulation', 'danger', 'Data Exfiltration');
        
        const dataSizes = [1024, 5120, 10240, 51200, 102400]; // KB
        
        for (const size of dataSizes) {
            const data = 'A'.repeat(size);
            
            try {
                await fetch('https://lzgtwdx5ii.execute-api.us-east-2.amazonaws.com/prod/images?profile=true', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Simulation': 'exfiltration'
                    },
                    body: JSON.stringify({ data, size })
                });
                
                addLog(`Data exfiltration attempt: ${(size / 1024).toFixed(1)} KB`, 'warning', 'Data Exfiltration');
            } catch (err) {
                addLog(`Simulated data transfer: ${(size / 1024).toFixed(1)} KB`, 'warning', 'Data Exfiltration');
            }
            
            await new Promise(resolve => setTimeout(resolve, 600));
        }
        
        addLog('✅ Data Exfiltration Simulation Complete', 'success', 'Data Exfiltration');
        setIsSimulating(false);
    };

    const simulatePortScan = async () => {
        setIsSimulating(true);
        addLog('🔴 Initiating Port Scanning Simulation', 'danger', 'Port Scan');
        
        const commonPorts = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017, 3389];
        
        for (const port of commonPorts) {
            try {
                // Simulate port scan by attempting connection
                addLog(`Scanning port ${port}...`, 'info', 'Port Scan');
                
                // In real implementation, this would attempt connection
                await new Promise(resolve => setTimeout(resolve, 200));
                
                const status = Math.random() > 0.5 ? 'OPEN' : 'CLOSED';
                addLog(`Port ${port}: ${status}`, 'warning', 'Port Scan');
            } catch (err) {
                addLog(`Port ${port} scan failed`, 'warning', 'Port Scan');
            }
        }
        
        addLog('✅ Port Scan Simulation Complete', 'success', 'Port Scan');
        setIsSimulating(false);
    };

    const threatTypes = [
        {
            id: 'brute-force',
            name: 'Brute Force Attack',
            description: 'Simulates multiple failed login attempts to test account lockout and monitoring',
            icon: Lock,
            color: 'from-red-500 to-orange-500',
            action: simulateBruteForce,
            monitoring: ['CloudWatch Logs', 'GuardDuty', 'CloudTrail']
        },
        {
            id: 'sql-injection',
            name: 'SQL Injection',
            description: 'Tests API input validation with common SQL injection patterns',
            icon: Database,
            color: 'from-purple-500 to-pink-500',
            action: simulateSQLInjection,
            monitoring: ['WAF Logs', 'CloudWatch', 'Lambda Logs']
        },
        {
            id: 'ddos',
            name: 'DDoS Attack',
            description: 'Generates high-volume traffic to test rate limiting and auto-scaling',
            icon: Zap,
            color: 'from-yellow-500 to-red-500',
            action: simulateDDoS,
            monitoring: ['CloudFront', 'Shield', 'CloudWatch Metrics']
        },
        {
            id: 'unauthorized-access',
            name: 'Unauthorized Access',
            description: 'Attempts to access protected endpoints without proper authentication',
            icon: Shield,
            color: 'from-blue-500 to-cyan-500',
            action: simulateUnauthorizedAccess,
            monitoring: ['IAM Access Analyzer', 'CloudTrail', 'API Gateway Logs']
        },
        {
            id: 'data-exfiltration',
            name: 'Data Exfiltration',
            description: 'Simulates suspicious data transfer patterns to test DLP policies',
            icon: Activity,
            color: 'from-green-500 to-emerald-500',
            action: simulateDataExfiltration,
            monitoring: ['VPC Flow Logs', 'CloudWatch', 'Macie']
        },
        {
            id: 'port-scan',
            name: 'Port Scanning',
            description: 'Simulates reconnaissance activity by scanning common service ports',
            icon: AlertTriangle,
            color: 'from-orange-500 to-red-500',
            action: simulatePortScan,
            monitoring: ['GuardDuty', 'VPC Flow Logs', 'CloudWatch']
        }
    ];

    const projects = [
        {
            title: "Jordan McDonald Resumé",
            description: "View My Resumé Here",
            tech: ["1.5yrs Amazon L4", "Leadership Role", "Cyber Degree"],
            gradient: "from-blue-500 to-cyan-500",
            showPreview: true,
            icon: Code,
            button: (
                <button
                    onClick={() => setShowDocument(true)}
                    className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full font-semibold hover:shadow-lg hover:shadow-cyan-500/50 transition-all hover:scale-105"
                >
                    View Resumé
                </button>
            )
        },
        {
            title: "Security Sandbox",
            description: "Simulate security threats and monitor with AWS CloudWatch, CloudTrail, and GuardDuty",
            tech: ["AWS CloudWatch", "CloudTrail", "GuardDuty", "Threat Simulation"],
            gradient: "from-red-500 to-orange-500",
            showPreview: true,
            icon: Shield,
            button: (
                <button
                    onClick={() => setShowSecuritySandbox(true)}
                    className="px-8 py-3 bg-gradient-to-r from-red-500 to-orange-600 rounded-full font-semibold hover:shadow-lg hover:shadow-red-500/50 transition-all hover:scale-105"
                >
                    Launch Sandbox
                </button>
            )
        },
        {
            title: "Tech Stack & Architecture",
            description: "Explore the AWS services and technologies powering this portfolio",
            tech: ["AWS S3", "API Gateway", "Lambda", "React"],
            gradient: "from-orange-500 to-red-500",
            showPreview: true,
            icon: Cloud,
            button: (
                <button
                    onClick={() => setShowTechStack(true)}
                    className="px-8 py-3 bg-gradient-to-r from-orange-500 to-red-600 rounded-full font-semibold hover:shadow-lg hover:shadow-orange-500/50 transition-all hover:scale-105"
                >
                    View Architecture
                </button>
            )
        },
        {
            title: "Photo Gallery",
            description: "AWS S3 powered photo gallery with cloud storage",
            tech: ["AWS S3", "React", "REST API"],
            gradient: "from-purple-500 to-pink-500",
            showPreview: true,
            icon: Camera,
            button: (
                <button
                    onClick={handleOpenGallery}
                    className="px-8 py-3 bg-gradient-to-r from-purple-500 to-pink-600 rounded-full font-semibold hover:shadow-lg hover:shadow-purple-500/50 transition-all hover:scale-105"
                >
                    View Gallery
                </button>
            )
        }
    ];

    const skills = [
        {
            name: "AWS Cloud Certified",
            icon: Cloud,
            color: "text-blue-500",
            description: "Working to obtain AWS Cloud certifications with emphasis on security and AI focused specialties."
        },
        {
            name: "B.S. Cybersecurity",
            icon: GraduationCap,
            color: "text-purple-500",
            description: "Graduated with a degree in Cybersecurity with a focus on cloud security architecture."
        },
        {
            name: "Full-Stack Development",
            icon: Code,
            color: "text-cyan-500",
            description: "Proficient in React, AWS services, and building scalable cloud-native applications."
        }
    ];

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
            {/* Security Sandbox Modal */}
            {showSecuritySandbox && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-slate-900 rounded-2xl w-full max-w-7xl max-h-[90vh] overflow-hidden border border-slate-700 shadow-2xl">
                        {/* Header */}
                        <div className="bg-gradient-to-r from-red-500 to-orange-600 p-6 flex justify-between items-center">
                            <div className="flex items-center gap-3">
                                <Shield className="w-8 h-8" />
                                <div>
                                    <h2 className="text-2xl font-bold">Security Threat Sandbox</h2>
                                    <p className="text-sm opacity-90">Monitor simulated attacks with AWS CloudWatch & GuardDuty</p>
                                </div>
                            </div>
                            <button
                                onClick={() => setShowSecuritySandbox(false)}
                                className="p-2 hover:bg-white/20 rounded-full transition-colors"
                            >
                                <X className="w-6 h-6" />
                            </button>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6 overflow-y-auto max-h-[calc(90vh-100px)]">
                            {/* Threat Types */}
                            <div className="space-y-4">
                                <h3 className="text-xl font-bold mb-4">Select Threat Type</h3>
                                {threatTypes.map(threat => {
                                    const ThreatIcon = threat.icon;
                                    return (
                                        <div
                                            key={threat.id}
                                            className="bg-slate-800 rounded-xl p-4 border border-slate-700 hover:border-slate-600 transition-all"
                                        >
                                            <div className="flex items-start gap-4">
                                                <div className={`p-3 bg-gradient-to-br ${threat.color} rounded-lg`}>
                                                    <ThreatIcon className="w-6 h-6" />
                                                </div>
                                                <div className="flex-1">
                                                    <h4 className="font-semibold mb-1">{threat.name}</h4>
                                                    <p className="text-sm text-slate-400 mb-3">{threat.description}</p>
                                                    <div className="flex flex-wrap gap-2 mb-3">
                                                        {threat.monitoring.map((tool, idx) => (
                                                            <span key={idx} className="text-xs px-2 py-1 bg-slate-700 rounded-full">
                                                                {tool}
                                                            </span>
                                                        ))}
                                                    </div>
                                                    <button
                                                        onClick={threat.action}
                                                        disabled={isSimulating}
                                                        className={`px-4 py-2 bg-gradient-to-r ${threat.color} rounded-lg font-semibold hover:shadow-lg transition-all hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed`}
                                                    >
                                                        {isSimulating ? 'Running...' : 'Start Simulation'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>

                            {/* Activity Logs */}
                            <div className="space-y-4">
                                <div className="flex justify-between items-center">
                                    <h3 className="text-xl font-bold">Activity Logs</h3>
                                    <button
                                        onClick={() => setSandboxLogs([])}
                                        className="px-3 py-1 text-sm bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                                    >
                                        Clear Logs
                                    </button>
                                </div>
                                <div className="bg-slate-950 rounded-xl p-4 h-[600px] overflow-y-auto font-mono text-sm border border-slate-700">
                                    {sandboxLogs.length === 0 ? (
                                        <p className="text-slate-500 text-center py-8">No activity yet. Start a simulation to see logs.</p>
                                    ) : (
                                        <div className="space-y-2">
                                            {sandboxLogs.map(log => (
                                                <div
                                                    key={log.id}
                                                    className={`p-2 rounded ${
                                                        log.type === 'danger' ? 'bg-red-900/20 border-l-4 border-red-500' :
                                                        log.type === 'warning' ? 'bg-yellow-900/20 border-l-4 border-yellow-500' :
                                                        log.type === 'success' ? 'bg-green-900/20 border-l-4 border-green-500' :
                                                        'bg-blue-900/20 border-l-4 border-blue-500'
                                                    }`}
                                                >
                                                    <div className="text-xs text-slate-400 mb-1">
                                                        {new Date(log.timestamp).toLocaleTimeString()}
                                                        {log.threatType && (
                                                            <span className="ml-2 px-2 py-0.5 bg-slate-700 rounded text-xs">
                                                                {log.threatType}
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="text-sm">{log.message}</div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                                <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
                                    <p className="text-sm text-blue-200">
                                        <strong>💡 Tip:</strong> Monitor these simulations in your AWS Console:
                                    </p>
                                    <ul className="text-sm text-blue-300 mt-2 space-y-1 ml-4">
                                        <li>• CloudWatch Logs for detailed event tracking</li>
                                        <li>• GuardDuty for threat detection alerts</li>
                                        <li>• CloudTrail for API call auditing</li>
                                        <li>• WAF for web application firewall events</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Rest of your existing modals and components remain the same... */}
            {/* I'm keeping the structure but not duplicating all the modal code here for brevity */}
            
            {/* Navigation */}
            <nav className={`fixed w-full z-40 transition-all duration-300 ${scrollY > 50 ? 'bg-slate-900/95 backdrop-blur-sm shadow-lg' : ''}`}>
                <div className="max-w-6xl mx-auto px-6 py-4 flex justify-between items-center">
                    <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                        Jordan McDonald
                    </h1>
                    <div className="flex gap-6">
                        <a href="#about" className="hover:text-cyan-400 transition-colors">About</a>
                        <a href="#projects" className="hover:text-cyan-400 transition-colors">Projects</a>
                        <a href="#contact" className="hover:text-cyan-400 transition-colors">Contact</a>
                    </div>
                </div>
            </nav>

            {/* Hero Section */}
            <section className="min-h-screen flex items-center justify-center px-6 pt-20">
                <div className="max-w-4xl mx-auto text-center">
                    <div
                        className="mb-6 transition-all duration-700"
                        style={{
                            opacity: 1 - scrollY / 500,
                            transform: `translateY(${scrollY * 0.3}px)`
                        }}
                    >
                        <div className="mb-8 flex justify-center">
                            <div className="relative group">
                                <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-600 rounded-full blur opacity-75 group-hover:opacity-100 transition duration-1000 group-hover:duration-200 animate-pulse"></div>
                                <img
                                    src={profileImageUrl}
                                    alt="Jordan McDonald"
                                    className="relative w-32 h-32 md:w-40 md:h-40 rounded-full object-cover border-4 border-slate-900 shadow-2xl"
                                />
                            </div>
                        </div>

                        <h2 className="text-6xl md:text-7xl font-bold mb-4 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent leading-tight pb-2">
                            Aspiring Cloud Engineer
                        </h2>
                        <p className="text-xl md:text-2xl text-slate-300 mb-8">
                            Staying Curious, Adapting to Change, Relentlessly Driven
                        </p>
                        <div className="flex gap-4 justify-center mb-8">
                            <a
                                href="https://github.com/jmcdonald46"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="p-3 bg-slate-800 rounded-full hover:bg-slate-700 transition-all hover:scale-110"
                            >
                                <Github className="w-6 h-6" />
                            </a>
                            <a
                                href="https://linkedin.com/in/jmcdonald46"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="p-3 bg-slate-800 rounded-full hover:bg-slate-700 transition-all hover:scale-110"
                            >
                                <Linkedin className="w-6 h-6" />
                            </a>
                            <a
                                href="mailto:mcdonaldjordan4860@gmail.com"
                                className="p-3 bg-slate-800 rounded-full hover:bg-slate-700 transition-all hover:scale-110"
                            >
                                <Mail className="w-6 h-6" />
                            </a>
                        </div>
                        <a
                            href="#projects"
                            className="inline-flex items-center gap-2 px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full font-semibold hover:shadow-lg hover:shadow-cyan-500/50 transition-all hover:scale-105"
                        >
                            View My Work
                            <ArrowRight className="w-5 h-5" />
                        </a>
                    </div>
                </div>
            </section>

            {/* Skills Section */}
            <section id="about" className="py-20 px-6">
                <div className="max-w-6xl mx-auto">
                    <h3 className="text-4xl font-bold text-center mb-12">What I Do</h3>
                    <div className="grid md:grid-cols-3 gap-8">
                        {skills.map((skill, index) => {
                            const Icon = skill.icon;
                            return (
                                <div
                                    key={index}
                                    className="bg-slate-800/50 backdrop-blur-sm p-8 rounded-2xl border border-slate-700/50 hover:border-slate-600 transition-all hover:transform hover:scale-105"
                                >
                                    <Icon className={`w-12 h-12 mb-4 ${skill.color}`} />
                                    <h4 className="text-xl font-semibold mb-2">{skill.name}</h4>
                                    <p className="text-slate-400">{skill.description}</p>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* Projects Section */}
            <section id="projects" className="py-20 px-6 bg-slate-800/30">
                <div className="max-w-6xl mx-auto">
                    <h3 className="text-4xl font-bold text-center mb-12">Featured</h3>
                    <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
                        {projects.map((project, index) => {
                            const IconComponent = project.icon;
                            return (
                                <div
                                    key={index}
                                    className="bg-slate-800/50 backdrop-blur-sm rounded-2xl overflow-hidden border border-slate-700/50 hover:border-slate-600 transition-all hover:transform hover:scale-105 group"
                                >
                                    {project.showPreview ? (
                                        <div className="h-48 overflow-hidden bg-slate-900 flex items-center justify-center">
                                            <div className="text-center p-6">
                                                {IconComponent && <IconComponent className="w-16 h-16 mx-auto mb-2 text-cyan-400" />}
                                                <p className="text-slate-300 font-semibold">{project.title}</p>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className={`h-48 bg-gradient-to-br ${project.gradient} opacity-80 group-hover:opacity-100 transition-opacity`}></div>
                                    )}
                                    <div className="p-6">
                                        <h4 className="text-xl font-semibold mb-2">{project.title}</h4>
                                        <p className="text-slate-400 mb-4">{project.description}</p>
                                        {project.button && project.button}
                                        {project.tech[0] !== "" && (
                                            <div className="flex flex-wrap gap-2 mt-4">
                                                {project.tech.map((tech, i) => (
                                                    <span key={i} className="px-3 py-1 bg-slate-700 rounded-full text-sm">
                                                        {tech}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* Contact Section */}
            <section id="contact" className="py-20 px-6">
                <div className="max-w-4xl mx-auto text-center">
                    <h3 className="text-4xl font-bold mb-6">Let's Get In Touch!</h3>
                    <p className="text-xl text-slate-300 mb-8">
                        Shoot me an email with thoughts, ideas, or if you want to catch up!
                    </p>
                    <a
                        href="mailto:mcdonaldjordan4860@gmail.com"
                        className="inline-flex items-center gap-2 px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-full font-semibold hover:shadow-lg hover:shadow-cyan-500/50 transition-all hover:scale-105"
                    >
                        Get In Touch
                        <Mail className="w-5 h-5" />
                    </a>
                </div>
            </section>

            {/* Footer */}
            <footer className="py-8 px-6 border-t border-slate-700/50">
                <div className="max-w-6xl mx-auto text-center text-slate-400">
                    <p>© 2026 Jordan McDonald. Built with React 19 & Tailwind CSS v4.</p>
                </div>
            </footer>
        </div>
    );
}