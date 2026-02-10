import React, { useState, useEffect } from 'react';
import { Github, Linkedin, Mail, ArrowRight, Code, Cloud, GraduationCap, Camera, X, RefreshCw, ChevronLeft, ChevronRight, Shield, AlertTriangle, Activity, Lock, Database, Zap, Globe, Search, TrendingUp, MapPin, Clock, Eye, Ban, CheckCircle } from 'lucide-react';

export default function App() {
    const [scrollY, setScrollY] = useState(0);
    const [showDocument, setShowDocument] = useState(false);
    const [showGallery, setShowGallery] = useState(false);
    const [showTechStack, setShowTechStack] = useState(false);
    const [showSecuritySandbox, setShowSecuritySandbox] = useState(false);
    const [showThreatIntel, setShowThreatIntel] = useState(false);
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

    const googleDocUrl = 'https://drive.google.com/file/d/18bjJPJpaDcBSij2CtWOtmNSL2iSB0G2y/view?usp=sharing';
    const documentUrl = googleDocUrl.replace('/view?usp=sharing', '/preview');

    useEffect(() => {
        const handleScroll = () => setScrollY(window.scrollY);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    useEffect(() => {
        const fetchProfileImage = async () => {
            try {
                const API_ENDPOINT = import.meta.env.VITE_IMAGES_API;
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

            const API_ENDPOINT = `${import.meta.env.VITE_IMAGES_API}?page=${page}&limit=${imagesPerPage}`;
            console.log('🔍 Fetching images from:', API_ENDPOINT);

            const response = await fetch(API_ENDPOINT);
            console.log('📡 Response status:', response.status, response.statusText);
            console.log('📡 Response headers:', Object.fromEntries(response.headers));

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ API Error Response:', errorText);
                throw new Error(`API returned ${response.status}: ${response.statusText}`);
            }

            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                console.error('❌ Expected JSON but got:', contentType);
                console.error('❌ Response body:', text.substring(0, 200));
                throw new Error('API returned non-JSON response');
            }

            const data = await response.json();
            console.log('✅ Successfully fetched data:', data);

            setImages(data.images || []);

            if (data.pagination) {
                setCurrentPage(data.pagination.currentPage);
                setTotalPages(data.pagination.totalPages);
                setTotalImages(data.pagination.totalImages);
            }
        } catch (err) {
            console.error('❌ Error fetching images:', err);
            setGalleryError(`Failed to load images: ${err.message}`);
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
        }, ...prev].slice(0, 100));
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
                const response = await fetch(import.meta.env.VITE_SECURITY_API, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Threat-Type': 'brute-force'
                    },
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
                await fetch(import.meta.env.VITE_SECURITY_API, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Threat-Type': 'sql-injection'
                    },
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
                fetch(import.meta.env.VITE_SECURITY_API, {
                    method: 'GET',
                    headers: {
                        'X-Simulation': 'ddos',
                        'X-Threat-Type': 'ddos'
                    }
                }).catch(() => { })
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
                await fetch(import.meta.env.VITE_SECURITY_API, {
                    method: 'GET',
                    headers: {
                        'Authorization': 'Bearer invalid_token',
                        'X-Simulation': 'unauthorized',
                        'X-Threat-Type': 'unauthorized-access'
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

        const dataSizes = [1024, 5120, 10240, 51200, 102400];

        for (const size of dataSizes) {
            const data = 'A'.repeat(size);

            try {
                await fetch(import.meta.env.VITE_SECURITY_API, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Simulation': 'exfiltration',
                        'X-Threat-Type': 'data-exfiltration'
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
                addLog(`Scanning port ${port}...`, 'info', 'Port Scan');
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
            title: "Threat Intelligence Dashboard",
            description: "Real-time global threat monitoring with feeds from abuse.ch, AbuseIPDB, and NIST NVD",
            tech: ["AWS Lambda", "Python", "Threat Intel APIs", "REST API"],
            gradient: "from-red-600 via-orange-500 to-yellow-500",
            showPreview: true,
            icon: AlertTriangle,
            button: (
                <button
                    onClick={() => setShowThreatIntel(true)}
                    className="px-8 py-3 bg-gradient-to-r from-red-500 to-orange-600 rounded-full font-semibold hover:shadow-lg hover:shadow-red-500/50 transition-all hover:scale-105 flex items-center gap-2 justify-center w-full"
                >
                    <Shield className="w-4 h-4" />
                    Launch Dashboard
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
            description: "Bachelor's degree in Cybersecurity with focus on network security, threat analysis, and secure system design."
        },
        {
            name: "Web Development w ReactJs",
            icon: Code,
            color: "text-yellow-500",
            description: "Building modern, responsive web applications using React, JavaScript, and contemporary development practices."
        }
    ];

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
            {/* Document Modal */}
            {showDocument && (
                <div className="fixed inset-0 bg-black bg-opacity-90 z-50 flex flex-col pt-20 md:pt-24 p-4 md:p-6">
                    <button
                        onClick={() => setShowDocument(false)}
                        className="mb-4 self-start z-[60] bg-cyan-500 hover:bg-cyan-600 text-white font-semibold px-4 py-2 md:px-6 md:py-3 rounded-lg transition shadow-lg hover:shadow-cyan-500/50 flex items-center gap-2"
                    >
                        <X className="w-4 h-4 md:w-5 md:h-5" />
                        Close Resumé
                    </button>
                    <div className="relative w-full max-w-6xl mx-auto flex-1 bg-slate-800 rounded-lg overflow-hidden flex flex-col">
                        {!pdfError ? (
                            <iframe
                                src={documentUrl}
                                className="w-full flex-1"
                                title="PDF Viewer"
                                onError={() => setPdfError(true)}
                                allow="autoplay"
                            />
                        ) : (
                            <div className="w-full flex-1 flex flex-col items-center justify-center p-4 md:p-8 text-center">
                                <Code className="w-16 h-16 md:w-20 md:h-20 text-cyan-400 mb-4 md:mb-6" />
                                <h3 className="text-xl md:text-2xl font-bold mb-3 md:mb-4">Unable to Display PDF</h3>
                                <p className="text-sm md:text-base text-slate-300 mb-6 md:mb-8 max-w-md">
                                    Your browser may not support inline PDF viewing. Please download the PDF to view it.
                                </p>
                                <a
                                    href={googleDocUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="bg-cyan-500 hover:bg-cyan-600 text-white font-semibold px-6 py-3 md:px-8 md:py-4 rounded-lg transition shadow-lg hover:shadow-cyan-500/50 inline-flex items-center gap-2 text-sm md:text-base"
                                >
                                    <ArrowRight className="w-4 h-4 md:w-5 md:h-5" />
                                    Open in Google Docs
                                </a>
                            </div>
                        )}
                        {!pdfError && (
                            <div className="p-4 md:p-6 border-t border-slate-700">
                                <a
                                    href={googleDocUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="w-full md:w-auto mx-auto bg-cyan-500 hover:bg-cyan-600 text-white font-semibold px-6 py-3 rounded-lg transition shadow-lg hover:shadow-cyan-500/50 inline-flex items-center justify-center gap-2 text-sm md:text-base"
                                >
                                    <ArrowRight className="w-4 h-4 md:w-5 md:h-5" />
                                    Open in Google Docs
                                </a>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Gallery Modal */}
            {showGallery && (
                <div className="fixed inset-0 bg-black bg-opacity-95 z-50 overflow-y-auto gallery-container">
                    <div className="min-h-screen py-20 md:py-24 px-4 md:px-6">
                        <div className="max-w-7xl mx-auto">
                            <div className="flex justify-between items-center mb-6">
                                <h2 className="text-2xl md:text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">
                                    Photo Gallery
                                </h2>
                                <button
                                    onClick={() => setShowGallery(false)}
                                    className="bg-purple-500 hover:bg-purple-600 text-white font-semibold px-4 py-2 md:px-6 md:py-3 rounded-lg transition shadow-lg hover:shadow-purple-500/50 flex items-center gap-2"
                                >
                                    <X className="w-4 h-4 md:w-5 md:h-5" />
                                    Close Gallery
                                </button>
                            </div>

                            {galleryLoading && (
                                <div className="flex items-center justify-center py-20">
                                    <div className="text-center">
                                        <div className="w-16 h-16 border-4 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                                        <p className="text-slate-300">Loading images...</p>
                                    </div>
                                </div>
                            )}

                            {galleryError && (
                                <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-6 max-w-md mx-auto">
                                    <h3 className="text-red-400 font-semibold mb-2">Error</h3>
                                    <p className="text-red-300 mb-4">{galleryError}</p>
                                    <button
                                        onClick={() => fetchImages(currentPage)}
                                        className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition flex items-center gap-2"
                                    >
                                        <RefreshCw className="w-4 h-4" />
                                        Retry
                                    </button>
                                </div>
                            )}

                            {!galleryLoading && !galleryError && images.length === 0 && (
                                <div className="text-center py-20">
                                    <Camera className="w-24 h-24 mx-auto text-slate-600 mb-4" />
                                    <h3 className="text-xl font-medium text-slate-400 mb-2">No photos found</h3>
                                    <p className="text-slate-500 max-w-md mx-auto">Upload some images to your S3 bucket to get started</p>
                                </div>
                            )}

                            {!galleryLoading && !galleryError && images.length > 0 && (
                                <>
                                    <div className="flex justify-between items-center mb-6">
                                        <p className="text-slate-400">
                                            Showing {((currentPage - 1) * imagesPerPage) + 1} to {Math.min(currentPage * imagesPerPage, totalImages)} of {totalImages} images
                                        </p>
                                    </div>

                                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                                        {images.map((image, index) => (
                                            <div
                                                key={index}
                                                className="group relative bg-slate-800 rounded-lg overflow-hidden cursor-pointer transform transition-all duration-300 hover:scale-105 hover:shadow-2xl hover:shadow-purple-500/20"
                                                onClick={() => setSelectedImage(image)}
                                            >
                                                <div className="aspect-square overflow-hidden">
                                                    <img
                                                        src={image.url}
                                                        alt={image.key}
                                                        className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-110"
                                                        loading="lazy"
                                                    />
                                                </div>
                                                <div className="p-4 border-t border-slate-700">
                                                    <p className="text-sm font-medium truncate mb-1">{image.key}</p>
                                                    <div className="flex justify-between items-center text-xs text-slate-400">
                                                        {image.size > 0 && (
                                                            <span>{formatFileSize(image.size)}</span>
                                                        )}
                                                        {image.lastModified && (
                                                            <span>{new Date(image.lastModified).toLocaleDateString()}</span>
                                                        )}
                                                    </div>
                                                </div>
                                                <div className="absolute inset-0 bg-gradient-to-t from-purple-900/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-end p-4">
                                                    <p className="text-white text-sm font-medium">Click to view full size</p>
                                                </div>
                                            </div>
                                        ))}
                                    </div>

                                    {totalPages > 1 && (
                                        <div className="flex justify-center items-center gap-2 mt-8">
                                            <button
                                                onClick={() => handlePageChange(currentPage - 1)}
                                                disabled={currentPage === 1}
                                                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed rounded-lg transition flex items-center gap-2 text-sm md:text-base"
                                            >
                                                <ChevronLeft className="w-4 h-4" />
                                                <span className="hidden sm:inline">Previous</span>
                                            </button>

                                            <div className="flex gap-2">
                                                {[...Array(totalPages)].map((_, idx) => {
                                                    const pageNum = idx + 1;
                                                    if (
                                                        pageNum === 1 ||
                                                        pageNum === totalPages ||
                                                        (pageNum >= currentPage - 1 && pageNum <= currentPage + 1)
                                                    ) {
                                                        return (
                                                            <button
                                                                key={pageNum}
                                                                onClick={() => handlePageChange(pageNum)}
                                                                className={`px-3 md:px-4 py-2 rounded-lg transition text-sm md:text-base ${currentPage === pageNum
                                                                    ? 'bg-purple-600 text-white font-semibold'
                                                                    : 'bg-slate-700 hover:bg-slate-600'
                                                                    }`}
                                                            >
                                                                {pageNum}
                                                            </button>
                                                        );
                                                    } else if (
                                                        pageNum === currentPage - 2 ||
                                                        pageNum === currentPage + 2
                                                    ) {
                                                        return <span key={pageNum} className="px-2 py-2 text-slate-500">...</span>;
                                                    }
                                                    return null;
                                                })}
                                            </div>

                                            <button
                                                onClick={() => handlePageChange(currentPage + 1)}
                                                disabled={currentPage === totalPages}
                                                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed rounded-lg transition flex items-center gap-2 text-sm md:text-base"
                                            >
                                                <span className="hidden sm:inline">Next</span>
                                                <ChevronRight className="w-4 h-4" />
                                            </button>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Full Image Modal */}
            {selectedImage && (
                <div
                    className="fixed inset-0 bg-black/95 z-[60] flex items-center justify-center p-4"
                    onClick={() => setSelectedImage(null)}
                >
                    <button
                        className="absolute top-4 right-4 text-white hover:text-purple-400 transition"
                        onClick={() => setSelectedImage(null)}
                    >
                        <X className="w-8 h-8" />
                    </button>
                    <div className="max-w-5xl max-h-full">
                        <img
                            src={selectedImage.url}
                            alt={selectedImage.key}
                            className="max-w-full max-h-[90vh] object-contain rounded-lg"
                            onClick={(e) => e.stopPropagation()}
                        />
                        <div className="text-white text-center mt-4">
                            <p className="font-medium">{selectedImage.key}</p>
                            {selectedImage.size > 0 && (
                                <p className="text-sm text-slate-300 mt-1">
                                    {formatFileSize(selectedImage.size)} • {new Date(selectedImage.lastModified).toLocaleDateString()}
                                </p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Security Sandbox Modal */}
            {showSecuritySandbox && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-slate-900 rounded-2xl w-full max-w-7xl max-h-[90vh] overflow-hidden border border-slate-700 shadow-2xl">
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
                                                    className={`p-2 rounded ${log.type === 'danger' ? 'bg-red-900/20 border-l-4 border-red-500' :
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

            {/* Tech Stack Modal */}
            {showTechStack && (
                <div className="fixed inset-0 bg-black bg-opacity-95 z-50 overflow-y-auto">
                    <div className="min-h-screen py-20 md:py-24 px-4 md:px-6">
                        <div className="max-w-6xl mx-auto">
                            <div className="flex justify-between items-center mb-8">
                                <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                                    Portfolio Architecture
                                </h2>
                                <button
                                    onClick={() => setShowTechStack(false)}
                                    className="bg-orange-500 hover:bg-orange-600 text-white font-semibold px-4 py-2 md:px-6 md:py-3 rounded-lg transition shadow-lg hover:shadow-orange-500/50 flex items-center gap-2"
                                >
                                    <X className="w-4 h-4 md:w-5 md:h-5" />
                                    Close
                                </button>
                            </div>

                            {/* Frontend Section */}
                            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-6 md:p-8 mb-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <Code className="w-8 h-8 text-cyan-400" />
                                    <h3 className="text-2xl font-bold">Frontend Architecture</h3>
                                </div>
                                <div className="grid md:grid-cols-2 gap-6">
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-700/30">
                                        <h4 className="text-lg font-semibold text-cyan-400 mb-3">React 19</h4>
                                        <p className="text-slate-300 mb-4">Modern React with hooks for state management and component architecture</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• useState for local state management</li>
                                            <li>• useEffect for side effects and API calls</li>
                                            <li>• Functional components throughout</li>
                                            <li>• Event-driven interactions</li>
                                        </ul>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-700/30">
                                        <h4 className="text-lg font-semibold text-cyan-400 mb-3">Tailwind CSS v4</h4>
                                        <p className="text-slate-300 mb-4">Utility-first CSS framework for responsive, modern design</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Responsive grid layouts</li>
                                            <li>• Custom gradient backgrounds</li>
                                            <li>• Hover effects and transitions</li>
                                            <li>• Mobile-first approach</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>

                            {/* AWS Cloud Section */}
                            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-6 md:p-8 mb-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <Cloud className="w-8 h-8 text-orange-400" />
                                    <h3 className="text-2xl font-bold">AWS Cloud Services</h3>
                                </div>
                                <div className="grid md:grid-cols-3 gap-6">
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-700/30">
                                        <h4 className="text-lg font-semibold text-orange-400 mb-3">S3 Storage</h4>
                                        <p className="text-slate-300 mb-4">Object storage for images and assets</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Scalable image hosting</li>
                                            <li>• Pre-signed URLs for security</li>
                                            <li>• Metadata tracking</li>
                                            <li>• Cost-effective storage</li>
                                        </ul>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-700/30">
                                        <h4 className="text-lg font-semibold text-orange-400 mb-3">API Gateway</h4>
                                        <p className="text-slate-300 mb-4">RESTful API endpoint management</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• HTTPS endpoints</li>
                                            <li>• Request/response handling</li>
                                            <li>• CORS configuration</li>
                                            <li>• Rate limiting</li>
                                        </ul>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-700/30">
                                        <h4 className="text-lg font-semibold text-orange-400 mb-3">Lambda Functions</h4>
                                        <p className="text-slate-300 mb-4">Serverless compute for backend logic</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Image retrieval logic</li>
                                            <li>• Pagination implementation</li>
                                            <li>• S3 integration</li>
                                            <li>• Auto-scaling</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>

                            {/* Security & Monitoring Section */}
                            <div className="bg-gradient-to-br from-red-900/20 to-orange-900/20 backdrop-blur-sm rounded-2xl border border-red-700/50 p-6 md:p-8 mb-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <GraduationCap className="w-8 h-8 text-red-400" />
                                    <h3 className="text-2xl font-bold">Security Sandbox & Monitoring</h3>
                                </div>
                                <p className="text-slate-300 mb-6">
                                    Interactive threat simulation environment demonstrating AWS security monitoring capabilities.
                                    This sandbox allows for controlled security testing while monitoring events across multiple AWS services.
                                </p>
                                <div className="grid md:grid-cols-3 gap-6 mb-6">
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-red-700/30">
                                        <h4 className="text-lg font-semibold text-red-400 mb-3">CloudWatch</h4>
                                        <p className="text-slate-300 mb-4">Centralized logging and monitoring</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Real-time log streaming</li>
                                            <li>• Custom metrics tracking</li>
                                            <li>• Log Insights queries</li>
                                            <li>• Automated dashboards</li>
                                        </ul>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-red-700/30">
                                        <h4 className="text-lg font-semibold text-red-400 mb-3">CloudTrail</h4>
                                        <p className="text-slate-300 mb-4">API activity auditing and governance</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• API call logging</li>
                                            <li>• Event history tracking</li>
                                            <li>• Compliance auditing</li>
                                            <li>• Security analysis</li>
                                        </ul>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-red-700/30">
                                        <h4 className="text-lg font-semibold text-red-400 mb-3">GuardDuty</h4>
                                        <p className="text-slate-300 mb-4">Intelligent threat detection service</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Automated threat detection</li>
                                            <li>• Anomaly identification</li>
                                            <li>• Security findings</li>
                                            <li>• Real-time alerts</li>
                                        </ul>
                                    </div>
                                </div>
                                <div className="bg-slate-900/30 rounded-lg p-6 border border-red-700/30">
                                    <h4 className="text-lg font-semibold text-red-300 mb-4">Simulated Threat Types</h4>
                                    <div className="grid md:grid-cols-2 gap-4">
                                        <div className="flex items-start gap-3">
                                            <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                                            <div>
                                                <p className="font-semibold text-red-300 text-sm">Brute Force Attacks</p>
                                                <p className="text-slate-400 text-xs">Multiple failed authentication attempts to test account lockout</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-3">
                                            <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                                            <div>
                                                <p className="font-semibold text-red-300 text-sm">SQL Injection</p>
                                                <p className="text-slate-400 text-xs">Malicious query patterns to test input validation</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-3">
                                            <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                                            <div>
                                                <p className="font-semibold text-red-300 text-sm">DDoS Simulation</p>
                                                <p className="text-slate-400 text-xs">High-volume traffic to test rate limiting and auto-scaling</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-3">
                                            <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                                            <div>
                                                <p className="font-semibold text-red-300 text-sm">Unauthorized Access</p>
                                                <p className="text-slate-400 text-xs">Protected endpoint access without proper authentication</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-3">
                                            <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                                            <div>
                                                <p className="font-semibold text-red-300 text-sm">Data Exfiltration</p>
                                                <p className="text-slate-400 text-xs">Suspicious data transfer patterns to test DLP policies</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-3">
                                            <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                                            <div>
                                                <p className="font-semibold text-red-300 text-sm">Port Scanning</p>
                                                <p className="text-slate-400 text-xs">Reconnaissance activity across common service ports</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Key Features Section */}
                            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-6 md:p-8 mb-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <GraduationCap className="w-8 h-8 text-purple-400" />
                                    <h3 className="text-2xl font-bold">Key Features Implemented</h3>
                                </div>
                                <div className="grid md:grid-cols-2 gap-4">
                                    <div className="flex items-start gap-3 bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                        <div className="w-2 h-2 bg-purple-400 rounded-full mt-2"></div>
                                        <div>
                                            <h4 className="font-semibold text-purple-400 mb-1">Serverless Architecture</h4>
                                            <p className="text-slate-400 text-sm">No servers to manage, automatic scaling, pay-per-use pricing</p>
                                        </div>
                                    </div>
                                    <div className="flex items-start gap-3 bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                        <div className="w-2 h-2 bg-purple-400 rounded-full mt-2"></div>
                                        <div>
                                            <h4 className="font-semibold text-purple-400 mb-1">REST API Integration</h4>
                                            <p className="text-slate-400 text-sm">Clean API design with pagination and error handling</p>
                                        </div>
                                    </div>
                                    <div className="flex items-start gap-3 bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                        <div className="w-2 h-2 bg-purple-400 rounded-full mt-2"></div>
                                        <div>
                                            <h4 className="font-semibold text-purple-400 mb-1">Responsive Design</h4>
                                            <p className="text-slate-400 text-sm">Mobile-first approach with seamless desktop experience</p>
                                        </div>
                                    </div>
                                    <div className="flex items-start gap-3 bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                        <div className="w-2 h-2 bg-purple-400 rounded-full mt-2"></div>
                                        <div>
                                            <h4 className="font-semibold text-purple-400 mb-1">Performance Optimization</h4>
                                            <p className="text-slate-400 text-sm">Lazy loading, efficient state management, optimized rendering</p>
                                        </div>
                                    </div>
                                    <div className="flex items-start gap-3 bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                        <div className="w-2 h-2 bg-purple-400 rounded-full mt-2"></div>
                                        <div>
                                            <h4 className="font-semibold text-purple-400 mb-1">Security Best Practices</h4>
                                            <p className="text-slate-400 text-sm">Pre-signed URLs, CORS policies, secure API endpoints</p>
                                        </div>
                                    </div>
                                    <div className="flex items-start gap-3 bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                                        <div className="w-2 h-2 bg-purple-400 rounded-full mt-2"></div>
                                        <div>
                                            <h4 className="font-semibold text-purple-400 mb-1">Modular Code Structure</h4>
                                            <p className="text-slate-400 text-sm">Component-based architecture for maintainability</p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Architecture Flow */}
                            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-6 md:p-8 mb-6">
                                <h3 className="text-2xl font-bold mb-6">Data Flow Architecture</h3>
                                <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                                    <div className="bg-cyan-500/10 border-2 border-cyan-500 rounded-lg p-4 text-center flex-1">
                                        <Code className="w-8 h-8 mx-auto mb-2 text-cyan-400" />
                                        <p className="font-semibold">React Frontend</p>
                                        <p className="text-xs text-slate-400 mt-1">User Interface</p>
                                    </div>
                                    <ArrowRight className="w-6 h-6 text-slate-500 hidden md:block" />
                                    <div className="bg-orange-500/10 border-2 border-orange-500 rounded-lg p-4 text-center flex-1">
                                        <Cloud className="w-8 h-8 mx-auto mb-2 text-orange-400" />
                                        <p className="font-semibold">API Gateway</p>
                                        <p className="text-xs text-slate-400 mt-1">REST Endpoint</p>
                                    </div>
                                    <ArrowRight className="w-6 h-6 text-slate-500 hidden md:block" />
                                    <div className="bg-purple-500/10 border-2 border-purple-500 rounded-lg p-4 text-center flex-1">
                                        <Code className="w-8 h-8 mx-auto mb-2 text-purple-400" />
                                        <p className="font-semibold">Lambda Function</p>
                                        <p className="text-xs text-slate-400 mt-1">Business Logic</p>
                                    </div>
                                    <ArrowRight className="w-6 h-6 text-slate-500 hidden md:block" />
                                    <div className="bg-blue-500/10 border-2 border-blue-500 rounded-lg p-4 text-center flex-1">
                                        <Camera className="w-8 h-8 mx-auto mb-2 text-blue-400" />
                                        <p className="font-semibold">S3 Storage</p>
                                        <p className="text-xs text-slate-400 mt-1">Image Assets</p>
                                    </div>
                                </div>
                            </div>

                            {/* Future Projects Section */}
                            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-6 md:p-8">
                                <div className="flex items-center gap-3 mb-6">
                                    <ArrowRight className="w-8 h-8 text-green-400" />
                                    <h3 className="text-2xl font-bold">Future Enhancements</h3>
                                </div>
                                <div className="grid md:grid-cols-3 gap-6">
                                    <div className="bg-gradient-to-br from-blue-900/30 to-cyan-900/30 rounded-lg p-6 border border-blue-500/30 hover:border-blue-500/60 transition-all">
                                        <div className="flex items-center gap-2 mb-4">
                                            <Cloud className="w-6 h-6 text-blue-400" />
                                            <h4 className="text-lg font-semibold text-blue-300">CloudFront CDN</h4>
                                        </div>
                                        <p className="text-slate-300 mb-4 text-sm">
                                            Integrate AWS CloudFront for global content delivery
                                        </p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Lower latency worldwide</li>
                                            <li>• Improved delivery times</li>
                                            <li>• Edge location caching</li>
                                            <li>• Enhanced user experience</li>
                                        </ul>
                                        <div className="mt-4 pt-4 border-t border-blue-500/20">
                                            <span className="text-xs text-blue-400 font-semibold">Status: Planned</span>
                                        </div>
                                    </div>

                                    <div className="bg-gradient-to-br from-red-900/30 to-orange-900/30 rounded-lg p-6 border border-red-500/30 hover:border-red-500/60 transition-all">
                                        <div className="flex items-center gap-2 mb-4">
                                            <GraduationCap className="w-6 h-6 text-red-400" />
                                            <h4 className="text-lg font-semibold text-red-300">Security Sandbox</h4>
                                        </div>
                                        <p className="text-slate-300 mb-4 text-sm">
                                            Interactive threat simulation with AWS security tools
                                        </p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• CloudWatch monitoring</li>
                                            <li>• GuardDuty threat detection</li>
                                            <li>• CloudTrail audit logging</li>
                                            <li>• 6 threat simulations</li>
                                        </ul>
                                        <div className="mt-4 pt-4 border-t border-red-500/20">
                                            <span className="text-xs text-green-400 font-semibold">Status: Active ✓</span>
                                        </div>
                                    </div>

                                    <div className="bg-gradient-to-br from-purple-900/30 to-pink-900/30 rounded-lg p-6 border border-purple-500/30 hover:border-purple-500/60 transition-all">
                                        <div className="flex items-center gap-2 mb-4">
                                            <Code className="w-6 h-6 text-purple-400" />
                                            <h4 className="text-lg font-semibold text-purple-300">AI Assistant Hub</h4>
                                        </div>
                                        <p className="text-slate-300 mb-4 text-sm">
                                            Interactive AI assistant powered by AWS AI services
                                        </p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li>• Amazon Bedrock integration</li>
                                            <li>• Natural language processing</li>
                                            <li>• SageMaker models</li>
                                            <li>• Real-time responses</li>
                                        </ul>
                                        <div className="mt-4 pt-4 border-t border-purple-500/20">
                                            <span className="text-xs text-purple-400 font-semibold">Status: Planned</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

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

            {/* Threat Intelligence Dashboard Modal */}
            {showThreatIntel && <ThreatIntelDashboard onClose={() => setShowThreatIntel(false)} />}
        </div>
    );
}

// Threat Intelligence Dashboard Component
const ThreatIntelDashboard = ({ onClose }) => {
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('overview');
    const [threatData, setThreatData] = useState({
        recentThreats: [],
        stats: {
            totalThreats: 0,
            criticalThreats: 0,
            blockedIPs: 0,
            activeCampaigns: 0
        },
        topMalware: [],
        threatActors: [],
        vulnerabilities: []
    });
    const [ipLookup, setIpLookup] = useState('');
    const [ipResult, setIpResult] = useState(null);
    const [ipLoading, setIpLoading] = useState(false);

    const fetchThreatData = async () => {
        setLoading(true);
        try {
            console.log('🔍 Fetching threat data from:', import.meta.env.VITE_THREAT_INTEL_API);
            const response = await fetch(import.meta.env.VITE_THREAT_INTEL_API);
            console.log('📡 Response status:', response.status, response.statusText);

            if (response.ok) {
                const data = await response.json();
                console.log('✅ Threat data received:', data);

                // Validate data structure
                if (data && data.stats && data.recentThreats !== undefined) {
                    setThreatData(data);
                } else {
                    console.warn('⚠️ Invalid data structure, using mock data');
                    loadMockData();
                }
            } else {
                console.warn('⚠️ API returned non-OK status, using mock data');
                loadMockData();
            }
        } catch (error) {
            console.error('❌ Error fetching threat data:', error);
            loadMockData();
        } finally {
            setLoading(false);
        }
    };

    const loadMockData = () => {
        setThreatData({
            recentThreats: [
                {
                    id: 1,
                    name: 'Emotet Botnet Activity',
                    severity: 'critical',
                    type: 'Malware',
                    timestamp: new Date().toISOString(),
                    source: 'abuse.ch',
                    description: 'Active botnet spreading via phishing campaigns',
                    indicators: ['192.168.1.100', '10.0.0.45'],
                    countries: ['US', 'DE', 'CN']
                },
                {
                    id: 2,
                    name: 'CVE-2024-1234 Exploitation',
                    severity: 'high',
                    type: 'Vulnerability',
                    timestamp: new Date(Date.now() - 3600000).toISOString(),
                    source: 'NIST NVD',
                    description: 'Remote code execution in Apache software',
                    indicators: ['CVE-2024-1234'],
                    countries: ['CN', 'RU']
                },
                {
                    id: 3,
                    name: 'Ransomware C2 Infrastructure',
                    severity: 'critical',
                    type: 'C2 Server',
                    timestamp: new Date(Date.now() - 7200000).toISOString(),
                    source: 'URLhaus',
                    description: 'Command and control server for LockBit variant',
                    indicators: ['malicious-domain.xyz', '203.0.113.42'],
                    countries: ['RU']
                },
                {
                    id: 4,
                    name: 'Credential Stuffing Campaign',
                    severity: 'medium',
                    type: 'Attack Campaign',
                    timestamp: new Date(Date.now() - 14400000).toISOString(),
                    source: 'OTX AlienVault',
                    description: 'Automated login attempts against financial institutions',
                    indicators: ['Multiple IPs'],
                    countries: ['BR', 'VN']
                },
                {
                    id: 5,
                    name: 'Cryptojacking Malware',
                    severity: 'medium',
                    type: 'Malware',
                    timestamp: new Date(Date.now() - 21600000).toISOString(),
                    source: 'abuse.ch',
                    description: 'XMRig miner deployment via compromised web servers',
                    indicators: ['cryptopool.example.com'],
                    countries: ['CN', 'IN']
                }
            ],
            stats: {
                totalThreats: 1247,
                criticalThreats: 89,
                blockedIPs: 5432,
                activeCampaigns: 23
            },
            topMalware: [
                { name: 'Emotet', count: 234, trend: 'up' },
                { name: 'TrickBot', count: 189, trend: 'down' },
                { name: 'Qakbot', count: 156, trend: 'up' },
                { name: 'IcedID', count: 143, trend: 'stable' },
                { name: 'Dridex', count: 98, trend: 'down' }
            ],
            threatActors: [
                { name: 'APT29 (Cozy Bear)', activity: 'high', targets: 'Government, Defense' },
                { name: 'Lazarus Group', activity: 'high', targets: 'Financial, Crypto' },
                { name: 'FIN7', activity: 'medium', targets: 'Retail, Hospitality' },
                { name: 'Sandworm', activity: 'medium', targets: 'Infrastructure, Energy' }
            ],
            vulnerabilities: [
                { cve: 'CVE-2024-1234', severity: 9.8, product: 'Apache HTTP Server', exploited: true },
                { cve: 'CVE-2024-5678', severity: 8.9, product: 'Microsoft Exchange', exploited: true },
                { cve: 'CVE-2024-9012', severity: 7.5, product: 'Cisco IOS', exploited: false },
                { cve: 'CVE-2024-3456', severity: 9.1, product: 'VMware vCenter', exploited: true }
            ]
        });
    };

    const lookupIP = async () => {
        if (!ipLookup.trim()) return;

        setIpLoading(true);
        setIpResult(null);

        try {
            const response = await fetch(`${import.meta.env.VITE_THREAT_INTEL_API}/lookup-ip?ip=${ipLookup}`);
            if (response.ok) {
                const data = await response.json();
                setIpResult(data);
            } else {
                setIpResult({
                    ip: ipLookup,
                    threat_score: Math.floor(Math.random() * 100),
                    is_malicious: Math.random() > 0.7,
                    country: 'United States',
                    city: 'San Francisco',
                    asn: 'AS15169 Google LLC',
                    last_seen: new Date().toISOString(),
                    categories: ['Scanning', 'Brute Force'],
                    sources: ['AbuseIPDB', 'OTX AlienVault']
                });
            }
        } catch (error) {
            console.error('Error looking up IP:', error);
            setIpResult({
                ip: ipLookup,
                threat_score: Math.floor(Math.random() * 100),
                is_malicious: Math.random() > 0.7,
                country: 'United States',
                city: 'San Francisco',
                asn: 'AS15169 Google LLC',
                last_seen: new Date().toISOString(),
                categories: ['Scanning', 'Brute Force'],
                sources: ['Mock Data']
            });
        } finally {
            setIpLoading(false);
        }
    };

    useEffect(() => {
        fetchThreatData();
        const interval = setInterval(fetchThreatData, 60000);
        return () => clearInterval(interval);
    }, []);

    const getSeverityBadge = (severity) => {
        const colors = {
            critical: 'bg-red-500/20 text-red-300 border-red-500/50',
            high: 'bg-orange-500/20 text-orange-300 border-orange-500/50',
            medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50',
            low: 'bg-blue-500/20 text-blue-300 border-blue-500/50'
        };
        return colors[severity] || colors.low;
    };

    const formatTimestamp = (timestamp) => {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);

        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    };

    return (
        <div className="fixed inset-0 bg-black/95 backdrop-blur-xl z-50 overflow-y-auto">
            <div className="min-h-screen p-4 md:p-8">
                <div className="max-w-7xl mx-auto mb-6">
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-4">
                            <div className="relative">
                                <Shield className="w-10 h-10 text-cyan-400" />
                                <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-pulse" />
                            </div>
                            <div>
                                <h2 className="text-3xl font-black tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-500">
                                    THREAT INTELLIGENCE
                                </h2>
                                <p className="text-slate-400 text-sm font-mono">Real-time global threat monitoring</p>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="p-2 hover:bg-slate-800 rounded-lg transition-colors text-slate-400 hover:text-white"
                        >
                            <X className="w-6 h-6" />
                        </button>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-cyan-500/30 rounded-xl p-4 relative overflow-hidden group hover:border-cyan-400/50 transition-all">
                            <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                            <div className="relative">
                                <Database className="w-5 h-5 text-cyan-400 mb-2" />
                                <div className="text-2xl font-black text-white mb-1">{threatData.stats.totalThreats.toLocaleString()}</div>
                                <div className="text-xs text-slate-400 uppercase tracking-wider font-mono">Total Threats</div>
                            </div>
                        </div>

                        <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-red-500/30 rounded-xl p-4 relative overflow-hidden group hover:border-red-400/50 transition-all">
                            <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                            <div className="relative">
                                <AlertTriangle className="w-5 h-5 text-red-400 mb-2" />
                                <div className="text-2xl font-black text-white mb-1">{threatData.stats.criticalThreats}</div>
                                <div className="text-xs text-slate-400 uppercase tracking-wider font-mono">Critical</div>
                            </div>
                        </div>

                        <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-purple-500/30 rounded-xl p-4 relative overflow-hidden group hover:border-purple-400/50 transition-all">
                            <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                            <div className="relative">
                                <Ban className="w-5 h-5 text-purple-400 mb-2" />
                                <div className="text-2xl font-black text-white mb-1">{threatData.stats.blockedIPs.toLocaleString()}</div>
                                <div className="text-xs text-slate-400 uppercase tracking-wider font-mono">Blocked IPs</div>
                            </div>
                        </div>

                        <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-orange-500/30 rounded-xl p-4 relative overflow-hidden group hover:border-orange-400/50 transition-all">
                            <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                            <div className="relative">
                                <Zap className="w-5 h-5 text-orange-400 mb-2" />
                                <div className="text-2xl font-black text-white mb-1">{threatData.stats.activeCampaigns}</div>
                                <div className="text-xs text-slate-400 uppercase tracking-wider font-mono">Active Campaigns</div>
                            </div>
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="flex gap-2 border-b border-slate-700 mb-6 overflow-x-auto">
                        {['overview', 'lookup', 'malware', 'actors', 'vulnerabilities'].map((tab) => (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`px-4 py-2 font-mono text-sm uppercase tracking-wider transition-all whitespace-nowrap ${activeTab === tab
                                    ? 'text-cyan-400 border-b-2 border-cyan-400'
                                    : 'text-slate-500 hover:text-slate-300'
                                    }`}
                            >
                                {tab}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Content */}
                <div className="max-w-7xl mx-auto">
                    {activeTab === 'overview' && (
                        <div className="space-y-4">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                                    <Activity className="w-5 h-5 text-cyan-400" />
                                    Recent Threat Activity
                                </h3>
                                <button
                                    onClick={fetchThreatData}
                                    disabled={loading}
                                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors text-sm text-slate-300 disabled:opacity-50"
                                >
                                    <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                                    Refresh
                                </button>
                            </div>

                            {threatData.recentThreats.map((threat) => (
                                <div
                                    key={threat.id}
                                    className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-6 hover:border-slate-600 transition-all group"
                                >
                                    <div className="flex items-start justify-between mb-4">
                                        <div className="flex-1">
                                            <div className="flex items-center gap-3 mb-2">
                                                <span className={`px-3 py-1 rounded-full text-xs font-bold border ${getSeverityBadge(threat.severity)} uppercase`}>
                                                    {threat.severity}
                                                </span>
                                                <span className="px-3 py-1 rounded-full text-xs font-mono bg-slate-700/50 text-slate-300 border border-slate-600">
                                                    {threat.type}
                                                </span>
                                                <span className="text-xs text-slate-500 font-mono flex items-center gap-1">
                                                    <Clock className="w-3 h-3" />
                                                    {formatTimestamp(threat.timestamp)}
                                                </span>
                                            </div>
                                            <h4 className="text-lg font-bold text-white mb-2 group-hover:text-cyan-400 transition-colors">
                                                {threat.name}
                                            </h4>
                                            <p className="text-slate-400 text-sm mb-3">{threat.description}</p>

                                            <div className="flex flex-wrap gap-2 mb-3">
                                                {threat.indicators.slice(0, 3).map((indicator, idx) => (
                                                    <code key={idx} className="px-2 py-1 bg-slate-950 rounded text-xs text-cyan-400 font-mono border border-slate-700">
                                                        {indicator}
                                                    </code>
                                                ))}
                                                {threat.indicators.length > 3 && (
                                                    <span className="px-2 py-1 text-xs text-slate-500 font-mono">
                                                        +{threat.indicators.length - 3} more
                                                    </span>
                                                )}
                                            </div>

                                            <div className="flex items-center gap-4 text-xs text-slate-500">
                                                <span className="flex items-center gap-1">
                                                    <Globe className="w-3 h-3" />
                                                    {threat.countries.join(', ')}
                                                </span>
                                                <span className="flex items-center gap-1">
                                                    <Database className="w-3 h-3" />
                                                    {threat.source}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {activeTab === 'lookup' && (
                        <div className="max-w-3xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-2 flex items-center gap-2">
                                    <Search className="w-6 h-6 text-cyan-400" />
                                    IP Address Threat Lookup
                                </h3>
                                <p className="text-slate-400 mb-6">Check any IP address against global threat intelligence databases</p>

                                <div className="flex gap-3 mb-6">
                                    <input
                                        type="text"
                                        value={ipLookup}
                                        onChange={(e) => setIpLookup(e.target.value)}
                                        onKeyPress={(e) => e.key === 'Enter' && lookupIP()}
                                        placeholder="Enter IP address (e.g., 192.168.1.1)"
                                        className="flex-1 px-4 py-3 bg-slate-950 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                                    />
                                    <button
                                        onClick={lookupIP}
                                        disabled={ipLoading}
                                        className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg font-bold text-white hover:shadow-lg hover:shadow-cyan-500/50 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                                    >
                                        {ipLoading ? (
                                            <>
                                                <RefreshCw className="w-5 h-5 animate-spin" />
                                                Scanning...
                                            </>
                                        ) : (
                                            <>
                                                <Eye className="w-5 h-5" />
                                                Lookup
                                            </>
                                        )}
                                    </button>
                                </div>

                                {ipResult && !ipResult.error && (
                                    <div className="border border-slate-700 rounded-xl p-6 bg-slate-950">
                                        <div className="flex items-start justify-between mb-6">
                                            <div>
                                                <div className="text-sm text-slate-500 mb-1 uppercase tracking-wider font-mono">Target IP</div>
                                                <div className="text-2xl font-mono font-bold text-white">{ipResult.ip}</div>
                                            </div>
                                            <div className={`px-4 py-2 rounded-lg font-bold text-sm ${ipResult.is_malicious
                                                ? 'bg-red-500/20 text-red-300 border border-red-500/50'
                                                : 'bg-green-500/20 text-green-300 border border-green-500/50'
                                                }`}>
                                                {ipResult.is_malicious ? (
                                                    <span className="flex items-center gap-2">
                                                        <AlertTriangle className="w-4 h-4" />
                                                        MALICIOUS
                                                    </span>
                                                ) : (
                                                    <span className="flex items-center gap-2">
                                                        <CheckCircle className="w-4 h-4" />
                                                        CLEAN
                                                    </span>
                                                )}
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-2 gap-4 mb-6">
                                            <div>
                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Threat Score</div>
                                                <div className="flex items-center gap-3">
                                                    <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                                                        <div
                                                            className={`h-full transition-all ${ipResult.threat_score > 70 ? 'bg-red-500' :
                                                                ipResult.threat_score > 40 ? 'bg-yellow-500' :
                                                                    'bg-green-500'
                                                                }`}
                                                            style={{ width: `${ipResult.threat_score}%` }}
                                                        />
                                                    </div>
                                                    <span className="text-white font-bold font-mono">{ipResult.threat_score}/100</span>
                                                </div>
                                            </div>
                                            <div>
                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Last Seen</div>
                                                <div className="text-white font-mono">{formatTimestamp(ipResult.last_seen)}</div>
                                            </div>
                                        </div>

                                        <div className="grid md:grid-cols-2 gap-6 mb-6">
                                            <div>
                                                <div className="text-xs text-slate-500 mb-2 uppercase tracking-wider font-mono">Location</div>
                                                <div className="space-y-1">
                                                    <div className="flex items-center gap-2 text-white">
                                                        <MapPin className="w-4 h-4 text-cyan-400" />
                                                        {ipResult.city}, {ipResult.country}
                                                    </div>
                                                    <div className="text-sm text-slate-400 font-mono">{ipResult.asn}</div>
                                                </div>
                                            </div>
                                            <div>
                                                <div className="text-xs text-slate-500 mb-2 uppercase tracking-wider font-mono">Threat Categories</div>
                                                <div className="flex flex-wrap gap-2">
                                                    {ipResult.categories.map((cat, idx) => (
                                                        <span key={idx} className="px-2 py-1 bg-red-500/20 text-red-300 border border-red-500/50 rounded text-xs font-mono">
                                                            {cat}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        </div>

                                        <div>
                                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wider font-mono">Intelligence Sources</div>
                                            <div className="flex flex-wrap gap-2">
                                                {ipResult.sources.map((source, idx) => (
                                                    <span key={idx} className="px-3 py-1 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 font-mono">
                                                        {source}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'malware' && (
                        <div className="max-w-4xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <AlertTriangle className="w-6 h-6 text-red-400" />
                                    Top Malware Families
                                </h3>

                                <div className="space-y-4">
                                    {threatData.topMalware.map((malware, idx) => (
                                        <div key={idx} className="flex items-center gap-4 p-4 bg-slate-950 border border-slate-700 rounded-lg hover:border-slate-600 transition-all">
                                            <div className="text-2xl font-bold text-slate-600 font-mono w-8">#{idx + 1}</div>
                                            <div className="flex-1">
                                                <div className="font-bold text-white mb-1">{malware.name}</div>
                                                <div className="flex items-center gap-2">
                                                    <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                                                        <div className="h-full bg-gradient-to-r from-red-500 to-orange-500" style={{ width: `${(malware.count / 234) * 100}%` }} />
                                                    </div>
                                                    <span className="text-sm text-slate-400 font-mono">{malware.count} detections</span>
                                                </div>
                                            </div>
                                            <div className={`flex items-center gap-1 text-sm font-mono ${malware.trend === 'up' ? 'text-red-400' :
                                                malware.trend === 'down' ? 'text-green-400' :
                                                    'text-slate-400'
                                                }`}>
                                                <TrendingUp className={`w-4 h-4 ${malware.trend === 'down' ? 'rotate-180' : malware.trend === 'stable' ? 'rotate-90' : ''}`} />
                                                {malware.trend}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'actors' && (
                        <div className="max-w-4xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <Shield className="w-6 h-6 text-purple-400" />
                                    Active Threat Actors
                                </h3>

                                <div className="grid gap-4">
                                    {threatData.threatActors.map((actor, idx) => (
                                        <div key={idx} className="p-6 bg-slate-950 border border-slate-700 rounded-lg hover:border-purple-500/50 transition-all group">
                                            <div className="flex items-start justify-between mb-3">
                                                <h4 className="font-bold text-lg text-white group-hover:text-purple-400 transition-colors">{actor.name}</h4>
                                                <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${actor.activity === 'high' ? 'bg-red-500/20 text-red-300 border border-red-500/50' :
                                                    'bg-yellow-500/20 text-yellow-300 border border-yellow-500/50'
                                                    }`}>
                                                    {actor.activity} activity
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-2 text-slate-400 text-sm">
                                                <span className="font-mono">Targets:</span>
                                                <span>{actor.targets}</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'vulnerabilities' && (
                        <div className="max-w-5xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <Zap className="w-6 h-6 text-yellow-400" />
                                    Recent Critical Vulnerabilities
                                </h3>

                                <div className="space-y-4">
                                    {threatData.vulnerabilities.map((vuln, idx) => (
                                        <div key={idx} className="p-6 bg-slate-950 border border-slate-700 rounded-lg hover:border-yellow-500/50 transition-all group">
                                            <div className="flex items-start justify-between mb-3">
                                                <div className="flex-1">
                                                    <div className="flex items-center gap-3 mb-2">
                                                        <code className="px-3 py-1 bg-slate-900 border border-slate-700 rounded text-cyan-400 font-mono text-sm">
                                                            {vuln.cve}
                                                        </code>
                                                        <span className={`px-2 py-1 rounded text-xs font-bold ${vuln.severity >= 9 ? 'bg-red-500/20 text-red-300 border border-red-500/50' :
                                                            vuln.severity >= 7 ? 'bg-orange-500/20 text-orange-300 border border-orange-500/50' :
                                                                'bg-yellow-500/20 text-yellow-300 border border-yellow-500/50'
                                                            }`}>
                                                            CVSS {vuln.severity}
                                                        </span>
                                                        {vuln.exploited && (
                                                            <span className="px-2 py-1 bg-red-500/20 text-red-300 border border-red-500/50 rounded text-xs font-bold uppercase flex items-center gap-1">
                                                                <AlertTriangle className="w-3 h-3" />
                                                                Actively Exploited
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className="text-white font-semibold">{vuln.product}</div>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};