import React, { useState, useEffect } from 'react';
import { Github, Linkedin, Mail, ArrowRight, Code, Cloud, GraduationCap, Camera, X, RefreshCw, ChevronLeft, ChevronRight, Shield, AlertTriangle, Activity, Lock, Database, Zap, Globe, Search, TrendingUp, MapPin, Clock, Eye, Ban, CheckCircle, Loader, AlertCircle, Info } from 'lucide-react';
// Profile image: Replace the URL below with your Imgur URL after uploading
import profileImage from './assets/IMGpfp.jpeg';

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
    const [profileImageUrl] = useState('https://jordanmcdonaldusprofileimage.s3.us-east-2.amazonaws.com/IMG_5770.jpeg');

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

    // Profile image is imported as a static asset (see import at top of file)

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
            description: "AWS Cloud Practitioner certified. Working on AWS Solutions Architect with emphasis on security and AI focused specialties to supplement the AWS certifications."
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

                            {/* Threat Intelligence Dashboard Section */}
                            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50 p-6 md:p-8 mb-6">
                                <div className="flex items-center gap-3 mb-6">
                                    <Database className="w-8 h-8 text-purple-400" />
                                    <h3 className="text-2xl font-bold">Threat Intelligence Dashboard</h3>
                                </div>
                                <p className="text-slate-300 mb-6">
                                    Real-time cybersecurity threat monitoring powered by multiple open-source intelligence feeds.
                                </p>

                                <div className="grid md:grid-cols-3 gap-6 mb-6">
                                    {/* URLhaus */}
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-orange-500/30">
                                        <div className="flex items-center gap-2 mb-3">
                                            <AlertTriangle className="w-6 h-6 text-orange-400" />
                                            <h4 className="text-lg font-semibold text-orange-400">URLhaus</h4>
                                        </div>
                                        <p className="text-slate-300 mb-3 text-sm">Malware distribution URL tracking</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li className="flex items-start gap-2">
                                                <span className="text-orange-400 mt-0.5">•</span>
                                                <span>Real-time malware URL feed</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-orange-400 mt-0.5">•</span>
                                                <span>Threat indicators and IOCs</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-orange-400 mt-0.5">•</span>
                                                <span>Malware family identification</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-orange-400 mt-0.5">•</span>
                                                <span>Abuse.ch community data</span>
                                            </li>
                                        </ul>
                                    </div>

                                    {/* Feodo Tracker */}
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-red-500/30">
                                        <div className="flex items-center gap-2 mb-3">
                                            <Globe className="w-6 h-6 text-red-400" />
                                            <h4 className="text-lg font-semibold text-red-400">Feodo Tracker</h4>
                                        </div>
                                        <p className="text-slate-300 mb-3 text-sm">C2 infrastructure monitoring</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li className="flex items-start gap-2">
                                                <span className="text-red-400 mt-0.5">•</span>
                                                <span>Botnet C2 server tracking</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-red-400 mt-0.5">•</span>
                                                <span>Active threat infrastructure</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-red-400 mt-0.5">•</span>
                                                <span>IP blocklist generation</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-red-400 mt-0.5">•</span>
                                                <span>Geolocation data</span>
                                            </li>
                                        </ul>
                                    </div>

                                    {/* AlienVault OTX */}
                                    <div className="bg-slate-900/50 rounded-lg p-6 border border-cyan-500/30">
                                        <div className="flex items-center gap-2 mb-3">
                                            <Shield className="w-6 h-6 text-cyan-400" />
                                            <h4 className="text-lg font-semibold text-cyan-400">AlienVault OTX</h4>
                                        </div>
                                        <p className="text-slate-300 mb-3 text-sm">Global threat intelligence pulses</p>
                                        <ul className="text-slate-400 text-sm space-y-2">
                                            <li className="flex items-start gap-2">
                                                <span className="text-cyan-400 mt-0.5">•</span>
                                                <span>Community threat sharing</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-cyan-400 mt-0.5">•</span>
                                                <span>Threat actor campaigns</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-cyan-400 mt-0.5">•</span>
                                                <span>Targeted country data</span>
                                            </li>
                                            <li className="flex items-start gap-2">
                                                <span className="text-cyan-400 mt-0.5">•</span>
                                                <span>CVE exploitation tracking</span>
                                            </li>
                                        </ul>
                                    </div>
                                </div>

                                {/* Data Processing Pipeline */}
                                <div className="bg-gradient-to-r from-purple-900/20 to-cyan-900/20 rounded-xl p-6 border border-purple-500/30 mb-6">
                                    <h4 className="text-lg font-semibold text-purple-300 mb-3 flex items-center gap-2">
                                        <Activity className="w-5 h-5" />
                                        Data Processing Pipeline
                                    </h4>
                                    <div className="grid md:grid-cols-4 gap-4 text-sm">
                                        <div className="text-center">
                                            <div className="bg-purple-500/20 rounded-lg p-3 mb-2">
                                                <Database className="w-6 h-6 mx-auto text-purple-400" />
                                            </div>
                                            <p className="text-slate-300 font-medium">API Ingestion</p>
                                            <p className="text-slate-500 text-xs mt-1">Fetch from sources</p>
                                        </div>
                                        <div className="text-center">
                                            <div className="bg-cyan-500/20 rounded-lg p-3 mb-2">
                                                <Code className="w-6 h-6 mx-auto text-cyan-400" />
                                            </div>
                                            <p className="text-slate-300 font-medium">Lambda Processing</p>
                                            <p className="text-slate-500 text-xs mt-1">Parse & normalize</p>
                                        </div>
                                        <div className="text-center">
                                            <div className="bg-orange-500/20 rounded-lg p-3 mb-2">
                                                <Shield className="w-6 h-6 mx-auto text-orange-400" />
                                            </div>
                                            <p className="text-slate-300 font-medium">Caching Layer</p>
                                            <p className="text-slate-500 text-xs mt-1">15-min TTL</p>
                                        </div>
                                        <div className="text-center">
                                            <div className="bg-green-500/20 rounded-lg p-3 mb-2">
                                                <Activity className="w-6 h-6 mx-auto text-green-400" />
                                            </div>
                                            <p className="text-slate-300 font-medium">Live Dashboard</p>
                                            <p className="text-slate-500 text-xs mt-1">Real-time updates</p>
                                        </div>
                                    </div>
                                </div>

                                {/* How It Works Section */}
                                <div className="bg-gradient-to-br from-slate-900 to-slate-950 rounded-xl p-6 border border-purple-500/30 mb-6">
                                    <h4 className="text-xl font-bold text-purple-300 mb-6 flex items-center gap-2">
                                        <Activity className="w-6 h-6" />
                                        How the Threat Dashboard Works
                                    </h4>

                                    <div className="space-y-6">
                                        {/* Step 1 */}
                                        <div className="flex gap-4">
                                            <div className="flex-shrink-0">
                                                <div className="w-10 h-10 rounded-full bg-purple-500/20 border-2 border-purple-500 flex items-center justify-center">
                                                    <span className="text-purple-300 font-bold">1</span>
                                                </div>
                                            </div>
                                            <div>
                                                <h5 className="font-semibold text-white mb-2">API Request from Frontend</h5>
                                                <p className="text-slate-400 text-sm">
                                                    React application sends GET request to AWS API Gateway endpoint when dashboard loads
                                                </p>
                                                <code className="block mt-2 px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-cyan-400 font-mono">
                                                    fetch(VITE_THREAT_INTEL_API)
                                                </code>
                                            </div>
                                        </div>

                                        {/* Step 2 */}
                                        <div className="flex gap-4">
                                            <div className="flex-shrink-0">
                                                <div className="w-10 h-10 rounded-full bg-cyan-500/20 border-2 border-cyan-500 flex items-center justify-center">
                                                    <span className="text-cyan-300 font-bold">2</span>
                                                </div>
                                            </div>
                                            <div>
                                                <h5 className="font-semibold text-white mb-2">Lambda Function Execution</h5>
                                                <p className="text-slate-400 text-sm mb-2">
                                                    Python Lambda function checks cache, then fetches from three threat intelligence APIs:
                                                </p>
                                                <div className="grid grid-cols-3 gap-2 mt-2">
                                                    <div className="px-2 py-1 bg-orange-500/10 border border-orange-500/30 rounded text-xs text-orange-300 text-center">
                                                        URLhaus API
                                                    </div>
                                                    <div className="px-2 py-1 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-300 text-center">
                                                        Feodo Tracker
                                                    </div>
                                                    <div className="px-2 py-1 bg-cyan-500/10 border border-cyan-500/30 rounded text-xs text-cyan-300 text-center">
                                                        AlienVault OTX
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Step 3 */}
                                        <div className="flex gap-4">
                                            <div className="flex-shrink-0">
                                                <div className="w-10 h-10 rounded-full bg-orange-500/20 border-2 border-orange-500 flex items-center justify-center">
                                                    <span className="text-orange-300 font-bold">3</span>
                                                </div>
                                            </div>
                                            <div>
                                                <h5 className="font-semibold text-white mb-2">Data Processing & Normalization</h5>
                                                <p className="text-slate-400 text-sm">
                                                    Lambda parses responses, filters by threat type, and normalizes data structure
                                                </p>
                                                <div className="mt-2 text-xs text-slate-500 space-y-1">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
                                                        <span>Malware URLs → malwareUrls[]</span>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                                                        <span>C2 Servers → c2Servers[]</span>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                                                        <span>OTX Pulses → otxIntelligence[]</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Step 4 */}
                                        <div className="flex gap-4">
                                            <div className="flex-shrink-0">
                                                <div className="w-10 h-10 rounded-full bg-green-500/20 border-2 border-green-500 flex items-center justify-center">
                                                    <span className="text-green-300 font-bold">4</span>
                                                </div>
                                            </div>
                                            <div>
                                                <h5 className="font-semibold text-white mb-2">Caching & Response</h5>
                                                <p className="text-slate-400 text-sm">
                                                    Data cached for 15 minutes (900s TTL), then returned as JSON to frontend
                                                </p>
                                                <div className="mt-2 px-3 py-2 bg-slate-950 border border-green-500/30 rounded text-xs">
                                                    <div className="flex items-center justify-between text-green-400">
                                                        <span>Cache Hit Rate:</span>
                                                        <span className="font-bold">~85%</span>
                                                    </div>
                                                    <div className="flex items-center justify-between text-green-400 mt-1">
                                                        <span>Response Time:</span>
                                                        <span className="font-bold">&lt;200ms</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Step 5 */}
                                        <div className="flex gap-4">
                                            <div className="flex-shrink-0">
                                                <div className="w-10 h-10 rounded-full bg-blue-500/20 border-2 border-blue-500 flex items-center justify-center">
                                                    <span className="text-blue-300 font-bold">5</span>
                                                </div>
                                            </div>
                                            <div>
                                                <h5 className="font-semibold text-white mb-2">Frontend Rendering</h5>
                                                <p className="text-slate-400 text-sm">
                                                    React components display threats in categorized tabs with real-time updates
                                                </p>
                                                <div className="mt-2 grid grid-cols-2 gap-2">
                                                    <div className="px-2 py-1 bg-slate-950 border border-slate-700 rounded text-xs text-slate-400">
                                                        📊 Overview Stats
                                                    </div>
                                                    <div className="px-2 py-1 bg-slate-950 border border-slate-700 rounded text-xs text-slate-400">
                                                        🟠 Malware URLs
                                                    </div>
                                                    <div className="px-2 py-1 bg-slate-950 border border-slate-700 rounded text-xs text-slate-400">
                                                        🔴 C2 Servers
                                                    </div>
                                                    <div className="px-2 py-1 bg-slate-950 border border-slate-700 rounded text-xs text-slate-400">
                                                        🔵 Threat Intel
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Key Features */}
                                    <div className="mt-6 pt-6 border-t border-slate-700">
                                        <h5 className="font-semibold text-white mb-3">Key Features</h5>
                                        <div className="grid md:grid-cols-2 gap-3">
                                            <div className="flex items-start gap-2">
                                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                                <span className="text-slate-300 text-sm">Serverless architecture - zero maintenance</span>
                                            </div>
                                            <div className="flex items-start gap-2">
                                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                                <span className="text-slate-300 text-sm">15-minute cache reduces API calls by 85%</span>
                                            </div>
                                            <div className="flex items-start gap-2">
                                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                                <span className="text-slate-300 text-sm">Real-time data from 3 threat sources</span>
                                            </div>
                                            <div className="flex items-start gap-2">
                                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                                <span className="text-slate-300 text-sm">Automatic fallback to mock data on errors</span>
                                            </div>
                                            <div className="flex items-start gap-2">
                                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                                <span className="text-slate-300 text-sm">Color-coded severity indicators</span>
                                            </div>
                                            <div className="flex items-start gap-2">
                                                <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                                <span className="text-slate-300 text-sm">Direct links to threat source pages</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Launch Dashboard Button */}
                                <div className="text-center">
                                    <button
                                        onClick={() => {
                                            setShowTechStack(false);
                                            setShowThreatIntel(true);
                                        }}
                                        className="inline-flex items-center gap-3 px-8 py-4 bg-gradient-to-r from-purple-500 to-cyan-600 hover:from-purple-600 hover:to-cyan-700 text-white rounded-xl font-bold text-lg transition-all hover:shadow-lg hover:shadow-purple-500/50 hover:scale-105">
                                        <Activity className="w-6 h-6" />
                                        Launch Threat Dashboard
                                        <ArrowRight className="w-5 h-5" />
                                    </button>
                                    <p className="text-slate-400 text-sm mt-3">
                                        Experience the live dashboard with real-time threat data
                                    </p>
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
                        <a href="#architecture" className="hover:text-cyan-400 transition-colors">Architecture</a>
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
                                    onError={(e) => {
                                        console.error('❌ Profile image failed to load');
                                        console.log('📍 Attempted to load:', e.target.src);
                                        // Fallback to avatar with initials
                                        e.target.src = 'https://ui-avatars.com/api/?name=Jordan+McDonald&size=200&background=0D9488&color=fff&bold=true';
                                    }}
                                />
                            </div>
                        </div>

                        <h2 className="text-6xl md:text-7xl font-bold mb-4 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent leading-tight pb-2">
                            Aspiring Cloud Engineer
                        </h2>

                        {/* Certification Badges */}
                        <div className="mb-6 flex justify-center">
                            <div className="space-y-4 px-6 py-4 bg-slate-800/50 backdrop-blur-sm rounded-2xl border border-slate-700/50">

                                {/* Completed Certifications */}
                                <div>
                                    <div className="text-center mb-3">
                                        <span className="inline-flex items-center gap-2 px-3 py-1 bg-green-500/20 border border-green-500/50 rounded-full text-green-300 text-xs font-semibold uppercase tracking-wider">
                                            <CheckCircle className="w-3 h-3" />
                                            Completed
                                        </span>
                                    </div>
                                    <div className="flex justify-center">
                                        {/* AWS Certified Cloud Practitioner */}
                                        <div className="group relative">
                                            <div className="absolute -inset-0.5 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-lg blur opacity-60 group-hover:opacity-100 transition duration-300"></div>
                                            <div className="relative bg-slate-900 px-4 py-2 rounded-lg flex items-center gap-2 border border-slate-700 hover:border-blue-500/50 transition-all">
                                                <Cloud className="w-5 h-5 text-blue-400" />
                                                <div className="text-left">
                                                    <div className="text-xs text-slate-400 font-medium">AWS</div>
                                                    <div className="text-sm font-bold text-white">Cloud Practitioner</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Work In Progress */}
                                <div>
                                    <div className="text-center mb-3">
                                        <span className="inline-flex items-center gap-2 px-3 py-1 bg-amber-500/20 border border-amber-500/50 rounded-full text-amber-300 text-xs font-semibold uppercase tracking-wider">
                                            <Activity className="w-3 h-3" />
                                            Work In Progress
                                        </span>
                                    </div>
                                    <div className="flex flex-wrap gap-3 justify-center">
                                        {/* AWS Certified Solutions Architect */}
                                        <div className="group relative">
                                            <div className="absolute -inset-0.5 bg-gradient-to-r from-orange-500 to-yellow-500 rounded-lg blur opacity-60 group-hover:opacity-100 transition duration-300"></div>
                                            <div className="relative bg-slate-900 px-4 py-2 rounded-lg flex items-center gap-2 border border-slate-700 hover:border-orange-500/50 transition-all">
                                                <Shield className="w-5 h-5 text-orange-400" />
                                                <div className="text-left">
                                                    <div className="text-xs text-slate-400 font-medium">AWS</div>
                                                    <div className="text-sm font-bold text-white">Solutions Architect</div>
                                                </div>
                                            </div>
                                        </div>

                                        {/* CompTIA Security+ */}
                                        <div className="group relative">
                                            <div className="absolute -inset-0.5 bg-gradient-to-r from-red-500 to-pink-500 rounded-lg blur opacity-60 group-hover:opacity-100 transition duration-300"></div>
                                            <div className="relative bg-slate-900 px-4 py-2 rounded-lg flex items-center gap-2 border border-slate-700 hover:border-red-500/50 transition-all">
                                                <Lock className="w-5 h-5 text-red-400" />
                                                <div className="text-left">
                                                    <div className="text-xs text-slate-400 font-medium">CompTIA</div>
                                                    <div className="text-sm font-bold text-white">Security+</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </div>

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

            {/* Technical Architecture Section */}
            <section id="architecture" className="py-20 px-6">
                <div className="container mx-auto max-w-6xl">
                    <div className="text-center mb-12">
                        <h2 className="text-4xl font-bold mb-4 bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                            Technical Architecture
                        </h2>
                        <div className="w-20 h-1 bg-gradient-to-r from-orange-400 to-red-500 mx-auto rounded-full"></div>
                    </div>

                    <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-2xl p-8">
                        <p className="text-slate-300 text-lg text-center mb-8">
                            A comprehensive overview of the technologies, services, and integrations powering this portfolio.
                        </p>

                        <button
                            onClick={() => setShowTechStack(true)}
                            className="mx-auto flex items-center gap-3 px-8 py-4 bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-600 hover:to-red-700 text-white rounded-xl font-bold text-lg transition-all hover:shadow-lg hover:shadow-orange-500/50 hover:scale-105">
                            <Cloud className="w-6 h-6" />
                            Explore Full Architecture
                            <ArrowRight className="w-5 h-5" />
                        </button>

                        {/* Quick Overview Cards */}
                        <div className="grid md:grid-cols-3 gap-6 mt-12">
                            <div className="bg-slate-950 border border-slate-700 rounded-xl p-6 hover:border-cyan-500/50 transition-all">
                                <Code className="w-10 h-10 text-cyan-400 mb-4" />
                                <h3 className="text-xl font-bold text-white mb-2">Frontend</h3>
                                <p className="text-slate-400 text-sm mb-4">Modern React application with real-time threat data visualization</p>
                                <div className="flex flex-wrap gap-2">
                                    <span className="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded text-xs">React 19</span>
                                    <span className="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded text-xs">Tailwind CSS</span>
                                    <span className="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded text-xs">Vite</span>
                                </div>
                            </div>

                            <div className="bg-slate-950 border border-slate-700 rounded-xl p-6 hover:border-orange-500/50 transition-all">
                                <Cloud className="w-10 h-10 text-orange-400 mb-4" />
                                <h3 className="text-xl font-bold text-white mb-2">AWS Infrastructure</h3>
                                <p className="text-slate-400 text-sm mb-4">Serverless architecture with scalable cloud services</p>
                                <div className="flex flex-wrap gap-2">
                                    <span className="px-2 py-1 bg-orange-500/10 text-orange-400 rounded text-xs">S3</span>
                                    <span className="px-2 py-1 bg-orange-500/10 text-orange-400 rounded text-xs">Lambda</span>
                                    <span className="px-2 py-1 bg-orange-500/10 text-orange-400 rounded text-xs">API Gateway</span>
                                </div>
                            </div>

                            <div className="bg-slate-950 border border-slate-700 rounded-xl p-6 hover:border-purple-500/50 transition-all">
                                <Database className="w-10 h-10 text-purple-400 mb-4" />
                                <h3 className="text-xl font-bold text-white mb-2">Threat Intelligence</h3>
                                <p className="text-slate-400 text-sm mb-4">Real-time data from multiple security sources</p>
                                <div className="flex flex-wrap gap-2">
                                    <span className="px-2 py-1 bg-purple-500/10 text-purple-400 rounded text-xs">URLhaus</span>
                                    <span className="px-2 py-1 bg-purple-500/10 text-purple-400 rounded text-xs">Feodo</span>
                                    <span className="px-2 py-1 bg-purple-500/10 text-purple-400 rounded text-xs">OTX</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

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
        vulnerabilities: [],
        malwareUrls: [],
        c2Servers: [],
        otxIntelligence: []
    });
    const [ipLookup, setIpLookup] = useState('');
    const [ipResult, setIpResult] = useState(null);
    const [ipLoading, setIpLoading] = useState(false);

    // IP Lookup state
    const [ipSearchQuery, setIpSearchQuery] = useState('');
    const [ipLookupResult, setIpLookupResult] = useState(null);
    const [ipLookupLoading, setIpLookupLoading] = useState(false);
    const [ipLookupError, setIpLookupError] = useState(null);
    const [recentSearches, setRecentSearches] = useState([]);

    // Malicious IP management state
    const [maliciousIPList, setMaliciousIPList] = useState([]);
    const [archivedIPList, setArchivedIPList] = useState([]);
    const [showArchived, setShowArchived] = useState(false);
    const [ipListLoading, setIpListLoading] = useState(false);
    const [lastUpdated, setLastUpdated] = useState(null);

    // Fetch malicious IPs from threat feeds (C2 servers, recent threats)
    const fetchMaliciousIPs = async () => {
        setIpListLoading(true);
        try {
            const response = await fetch(import.meta.env.VITE_THREAT_INTEL_API);

            if (response.ok) {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const data = await response.json();

                    // Extract IPs from C2 servers and recent threats
                    const extractedIPs = [];

                    // From C2 servers
                    if (data.recentThreats) {
                        data.recentThreats.forEach(threat => {
                            if (threat.indicators && Array.isArray(threat.indicators)) {
                                threat.indicators.forEach(indicator => {
                                    // Check if it's a valid IP
                                    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
                                    if (ipPattern.test(indicator)) {
                                        extractedIPs.push({
                                            ip: indicator,
                                            description: threat.description || threat.name,
                                            threatTypes: [threat.type || 'Unknown'],
                                            severity: threat.severity || 'medium',
                                            lastSeen: threat.timestamp || new Date().toISOString(),
                                            source: threat.source || 'Threat Feed'
                                        });
                                    }
                                });
                            }
                        });
                    }

                    // If we got IPs from the feed, use them; otherwise use fallback
                    if (extractedIPs.length > 0) {
                        // Remove duplicates
                        const uniqueIPs = Array.from(new Map(extractedIPs.map(item => [item.ip, item])).values());

                        // Move old IPs to archive and keep new ones
                        updateIPLists(uniqueIPs);
                        setLastUpdated(new Date().toISOString());
                        console.log('✅ Loaded', uniqueIPs.length, 'malicious IPs from threat feed');
                    } else {
                        loadFallbackIPs();
                    }
                } else {
                    loadFallbackIPs();
                }
            } else {
                loadFallbackIPs();
            }
        } catch (error) {
            console.error('Error fetching malicious IPs:', error);
            loadFallbackIPs();
        } finally {
            setIpListLoading(false);
        }
    };

    // Update IP lists - move old IPs to archive, keep recent ones active
    const updateIPLists = (newIPs) => {
        const now = new Date();
        const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

        // Separate into active (last 7 days) and archived (older)
        const active = [];
        const archived = [];

        newIPs.forEach(ip => {
            const lastSeenDate = new Date(ip.lastSeen);
            if (lastSeenDate > sevenDaysAgo) {
                active.push(ip);
            } else {
                archived.push(ip);
            }
        });

        // Keep existing archived IPs and add newly archived ones
        setArchivedIPList(prev => {
            const combined = [...archived, ...prev];
            // Remove duplicates and limit to 50 archived IPs
            return Array.from(new Map(combined.map(item => [item.ip, item])).values()).slice(0, 50);
        });

        // Set active IPs (limit to 12 most recent)
        setMaliciousIPList(active.slice(0, 12));
    };

    // Fallback IPs if API fails or returns no data
    const loadFallbackIPs = () => {
        const fallbackIPs = [
            {
                ip: '185.220.101.1',
                description: 'Known Tor exit node - frequently used for anonymous malicious activity',
                threatTypes: ['Anonymization', 'Potential C2'],
                severity: 'high',
                lastSeen: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '45.142.214.208',
                description: 'Active botnet C2 server - associated with Emotet campaigns',
                threatTypes: ['C2 Server', 'Malware Distribution'],
                severity: 'critical',
                lastSeen: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '103.75.201.2',
                description: 'Brute force attacks targeting SSH and RDP services',
                threatTypes: ['Brute Force', 'SSH Attack'],
                severity: 'high',
                lastSeen: new Date().toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '194.180.48.100',
                description: 'Cryptocurrency mining malware distribution',
                threatTypes: ['Cryptojacking', 'Malware'],
                severity: 'medium',
                lastSeen: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '91.229.77.64',
                description: 'Port scanning and network reconnaissance activity',
                threatTypes: ['Port Scan', 'Reconnaissance'],
                severity: 'medium',
                lastSeen: new Date().toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '5.188.10.180',
                description: 'Phishing campaign infrastructure - credential harvesting',
                threatTypes: ['Phishing', 'Credential Theft'],
                severity: 'critical',
                lastSeen: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '185.56.80.65',
                description: 'DDoS botnet participant - multiple attack campaigns',
                threatTypes: ['DDoS', 'Botnet'],
                severity: 'high',
                lastSeen: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '167.172.248.53',
                description: 'Ransomware delivery and command infrastructure',
                threatTypes: ['Ransomware', 'C2 Server'],
                severity: 'critical',
                lastSeen: new Date().toISOString(),
                source: 'Manual Curation'
            },
            // Add some older IPs for the archive
            {
                ip: '198.51.100.45',
                description: 'Previously active botnet infrastructure - now dormant',
                threatTypes: ['Botnet', 'Historical'],
                severity: 'medium',
                lastSeen: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '203.0.113.77',
                description: 'Old phishing campaign server - decommissioned',
                threatTypes: ['Phishing', 'Historical'],
                severity: 'low',
                lastSeen: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            },
            {
                ip: '192.0.2.88',
                description: 'Expired malware C2 - no longer active',
                threatTypes: ['C2 Server', 'Historical'],
                severity: 'low',
                lastSeen: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
                source: 'Manual Curation'
            }
        ];

        updateIPLists(fallbackIPs);
        setLastUpdated(new Date().toISOString());
        console.log('✅ Loaded fallback malicious IPs');
    };

    // Load malicious IPs on component mount
    useEffect(() => {
        fetchMaliciousIPs();
        // Update every hour
        const interval = setInterval(fetchMaliciousIPs, 60 * 60 * 1000);
        return () => clearInterval(interval);
    }, []);

    const fetchThreatData = async () => {
        setLoading(true);
        try {
            console.log('🔍 Fetching threat data from:', import.meta.env.VITE_THREAT_INTEL_API);
            const response = await fetch(import.meta.env.VITE_THREAT_INTEL_API);
            console.log('📡 Response status:', response.status, response.statusText);

            if (response.ok) {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const data = await response.json();
                    console.log('✅ Threat data received:', data);

                    // Separate different threat types
                    const malwareUrls = data.recentThreats?.filter(t => t.type === 'Malware URL') || [];
                    const c2Servers = data.recentThreats?.filter(t => t.type === 'C2 Server') || [];
                    const otxIntelligence = data.recentThreats?.filter(t => t.type === 'Threat Intelligence') || [];

                    // Validate data structure
                    if (data && data.stats && data.recentThreats !== undefined) {
                        setThreatData({
                            ...data,
                            malwareUrls,
                            c2Servers,
                            otxIntelligence
                        });
                    } else {
                        console.warn('⚠️ Invalid data structure, using mock data');
                        loadMockData();
                    }
                } else {
                    console.warn('⚠️ API returned non-JSON response (got', contentType, '), using mock data');
                    loadMockData();
                }
            } else {
                console.warn('⚠️ API returned non-OK status:', response.status, 'using mock data');
                loadMockData();
            }
        } catch (error) {
            console.error('❌ Error fetching threat data:', error.message);
            console.warn('⚠️ Using mock data instead');
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

    // Load recent IP searches from localStorage
    useEffect(() => {
        const saved = localStorage.getItem('recentIpSearches');
        if (saved) {
            try {
                setRecentSearches(JSON.parse(saved));
            } catch (e) {
                console.error('Failed to load recent searches:', e);
            }
        }
    }, []);

    // IP Lookup Functions
    const validateIP = (ip) => {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipv4Regex.test(ip)) return false;

        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    };

    const handleIPLookup = async (ip = ipSearchQuery) => {
        const searchIP = ip.trim();

        if (!searchIP) {
            setIpLookupError('Please enter an IP address');
            return;
        }

        if (!validateIP(searchIP)) {
            setIpLookupError('Please enter a valid IPv4 address (e.g., 8.8.8.8)');
            return;
        }

        setIpLookupLoading(true);
        setIpLookupError(null);
        setIpLookupResult(null);

        try {
            const API_ENDPOINT = `${import.meta.env.VITE_THREAT_INTEL_API}/lookup-ip?ip=${encodeURIComponent(searchIP)}`;
            console.log('🔍 Looking up IP:', searchIP);

            const response = await fetch(API_ENDPOINT);

            if (!response.ok) {
                throw new Error(`API returned ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            console.log('✅ IP Lookup result:', data);

            setIpLookupResult(data);

            // Add to recent searches (max 5)
            const updatedSearches = [
                { ip: searchIP, timestamp: new Date().toISOString(), threat_score: data.threat_score },
                ...recentSearches.filter(s => s.ip !== searchIP)
            ].slice(0, 5);

            setRecentSearches(updatedSearches);
            localStorage.setItem('recentIpSearches', JSON.stringify(updatedSearches));

        } catch (err) {
            console.error('❌ Error looking up IP:', err);
            setIpLookupError(`Failed to lookup IP: ${err.message}`);
        } finally {
            setIpLookupLoading(false);
        }
    };

    const getThreatLevel = (score) => {
        if (score >= 75) return { level: 'CRITICAL', color: 'text-red-400', bgColor: 'bg-red-500/20', borderColor: 'border-red-500' };
        if (score >= 50) return { level: 'HIGH', color: 'text-orange-400', bgColor: 'bg-orange-500/20', borderColor: 'border-orange-500' };
        if (score >= 25) return { level: 'MEDIUM', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20', borderColor: 'border-yellow-500' };
        return { level: 'LOW', color: 'text-green-400', bgColor: 'bg-green-500/20', borderColor: 'border-green-500' };
    };

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

    const getSeverityColor = (severity) => {
        const severityLower = severity?.toLowerCase() || 'medium';
        if (severityLower === 'critical') return 'bg-red-500/20 text-red-300 border-red-500/50';
        if (severityLower === 'high') return 'bg-orange-500/20 text-orange-300 border-orange-500/50';
        if (severityLower === 'medium') return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50';
        return 'bg-blue-500/20 text-blue-300 border-blue-500/50';
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


                    {/* Tabs */}
                    <div className="border-b border-slate-700 mb-6">
                        <div className="flex gap-4 overflow-x-auto">
                            {[
                                { id: 'overview', label: 'Overview', icon: Activity },
                                { id: 'iplookup', label: 'IP Lookup', icon: Search },
                                { id: 'malware', label: 'Malware URLs', icon: AlertTriangle, count: threatData.malwareUrls?.length },
                                { id: 'c2', label: 'C2 Servers', icon: Globe, count: threatData.c2Servers?.length },
                                { id: 'intelligence', label: 'Threat Intelligence', icon: Database, count: threatData.otxIntelligence?.length },
                                { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Shield, count: threatData.vulnerabilities?.length }
                            ].map((tab) => (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveTab(tab.id)}
                                    className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-all whitespace-nowrap ${activeTab === tab.id
                                        ? 'border-cyan-500 text-cyan-400'
                                        : 'border-transparent text-slate-400 hover:text-slate-300'
                                        }`}>
                                    <tab.icon className="w-4 h-4" />
                                    {tab.label}
                                    {tab.count !== undefined && (
                                        <span className="px-2 py-0.5 bg-slate-700 rounded text-xs">{tab.count}</span>
                                    )}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Content */}
                <div className="max-w-7xl mx-auto">
                    {activeTab === 'overview' && (
                        <div className="space-y-6">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <Activity className="w-6 h-6 text-cyan-400" />
                                    Threat Intelligence Overview
                                </h3>
                                <p className="text-slate-300 text-lg">
                                    This dashboard aggregates real-time threat intelligence from multiple sources.
                                    Use the tabs above to explore different threat categories.
                                </p>

                                <div className="mt-8 grid md:grid-cols-2 gap-6">
                                    <div className="p-6 bg-slate-950 border border-slate-700 rounded-lg">
                                        <h4 className="text-lg font-semibold text-white mb-3">Data Sources</h4>
                                        <ul className="space-y-2 text-slate-300">
                                            <li className="flex items-center gap-2">
                                                <div className="w-2 h-2 bg-orange-400 rounded-full"></div>
                                                URLhaus - Malware distribution URLs
                                            </li>
                                            <li className="flex items-center gap-2">
                                                <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                                                Feodo Tracker - C2 infrastructure
                                            </li>
                                            <li className="flex items-center gap-2">
                                                <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                                                AlienVault OTX - Threat intelligence pulses
                                            </li>
                                            <li className="flex items-center gap-2">
                                                <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                                                NVD - Vulnerability database
                                            </li>
                                        </ul>
                                    </div>

                                    <div className="p-6 bg-slate-950 border border-slate-700 rounded-lg">
                                        <h4 className="text-lg font-semibold text-white mb-3">Quick Actions</h4>
                                        <div className="space-y-3">
                                            <button
                                                onClick={() => setActiveTab('malware')}
                                                className="w-full flex items-center gap-2 px-4 py-3 bg-orange-500/10 hover:bg-orange-500/20 text-orange-300 border border-orange-500/30 rounded-lg transition-all">
                                                <AlertTriangle className="w-5 h-5" />
                                                View Malware URLs
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('c2')}
                                                className="w-full flex items-center gap-2 px-4 py-3 bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 rounded-lg transition-all">
                                                <Globe className="w-5 h-5" />
                                                View C2 Servers
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('intelligence')}
                                                className="w-full flex items-center gap-2 px-4 py-3 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg transition-all">
                                                <Database className="w-5 h-5" />
                                                View Threat Intelligence
                                            </button>
                                            <button
                                                onClick={() => setActiveTab('vulnerabilities')}
                                                className="w-full flex items-center gap-2 px-4 py-3 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg transition-all">
                                                <Shield className="w-5 h-5" />
                                                View Vulnerabilities
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'iplookup' && (
                        <div className="max-w-5xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-cyan-500/30 rounded-xl p-6 shadow-2xl">
                                <div className="flex items-center gap-3 mb-6">
                                    <Search className="w-6 h-6 text-cyan-400" />
                                    <h3 className="text-2xl font-bold text-white">IP Address Threat Lookup</h3>
                                </div>

                                {/* Search Bar */}
                                <div className="flex gap-3 mb-4">
                                    <div className="flex-1 relative">
                                        <input
                                            type="text"
                                            value={ipSearchQuery}
                                            onChange={(e) => setIpSearchQuery(e.target.value)}
                                            onKeyPress={(e) => e.key === 'Enter' && handleIPLookup()}
                                            placeholder="Enter IP address (e.g., 8.8.8.8)"
                                            className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
                                            disabled={ipLookupLoading}
                                        />
                                        {ipSearchQuery && (
                                            <button
                                                onClick={() => setIpSearchQuery('')}
                                                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white transition-colors"
                                            >
                                                <X className="w-4 h-4" />
                                            </button>
                                        )}
                                    </div>
                                    <button
                                        onClick={() => handleIPLookup()}
                                        disabled={ipLookupLoading}
                                        className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-700 disabled:to-slate-600 disabled:cursor-not-allowed rounded-lg font-semibold transition-all flex items-center gap-2"
                                    >
                                        {ipLookupLoading ? (
                                            <>
                                                <Loader className="w-5 h-5 animate-spin" />
                                                Searching...
                                            </>
                                        ) : (
                                            <>
                                                <Search className="w-5 h-5" />
                                                Lookup
                                            </>
                                        )}
                                    </button>
                                </div>

                                {/* Recent Searches */}
                                {recentSearches.length > 0 && !ipLookupResult && (
                                    <div className="mb-4">
                                        <div className="text-xs text-slate-400 mb-2 uppercase tracking-wider font-mono">Recent Searches</div>
                                        <div className="flex flex-wrap gap-2">
                                            {recentSearches.map((search, idx) => {
                                                const threat = getThreatLevel(search.threat_score);
                                                return (
                                                    <button
                                                        key={idx}
                                                        onClick={() => {
                                                            setIpSearchQuery(search.ip);
                                                            handleIPLookup(search.ip);
                                                        }}
                                                        className={`px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border ${threat.borderColor} rounded-lg text-sm font-mono transition-all flex items-center gap-2`}
                                                    >
                                                        <span className="text-slate-300">{search.ip}</span>
                                                        <span className={`text-xs ${threat.color}`}>{threat.level}</span>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {/* Error Display */}
                                {ipLookupError && (
                                    <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg flex items-start gap-3">
                                        <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                                        <div>
                                            <div className="font-semibold text-red-400">Error</div>
                                            <div className="text-sm text-red-300">{ipLookupError}</div>
                                        </div>
                                    </div>
                                )}

                                {/* Results Display */}
                                {ipLookupResult && (
                                    <div className="space-y-4 animate-fadeIn">
                                        {/* Threat Score Header */}
                                        <div className={`p-6 ${getThreatLevel(ipLookupResult.threat_score).bgColor} border-2 ${getThreatLevel(ipLookupResult.threat_score).borderColor} rounded-xl`}>
                                            <div className="flex items-center justify-between mb-4">
                                                <div>
                                                    <div className="text-sm text-slate-400 mb-1 font-mono">IP ADDRESS</div>
                                                    <div className="text-3xl font-bold font-mono">{ipLookupResult.ip}</div>
                                                </div>
                                                <div className="text-right">
                                                    <div className="text-sm text-slate-400 mb-1 font-mono">THREAT SCORE</div>
                                                    <div className={`text-5xl font-bold ${getThreatLevel(ipLookupResult.threat_score).color}`}>
                                                        {ipLookupResult.threat_score}
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                {ipLookupResult.is_malicious ? (
                                                    <>
                                                        <Ban className="w-5 h-5 text-red-400" />
                                                        <span className="text-red-400 font-semibold">Malicious Activity Detected</span>
                                                    </>
                                                ) : (
                                                    <>
                                                        <CheckCircle className="w-5 h-5 text-green-400" />
                                                        <span className="text-green-400 font-semibold">No Malicious Activity Detected</span>
                                                    </>
                                                )}
                                                <span className={`ml-auto px-3 py-1 ${getThreatLevel(ipLookupResult.threat_score).bgColor} border ${getThreatLevel(ipLookupResult.threat_score).borderColor} rounded-full text-sm font-bold`}>
                                                    {getThreatLevel(ipLookupResult.threat_score).level}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Details Grid */}
                                        <div className="grid md:grid-cols-2 gap-4">
                                            {/* Location Info */}
                                            <div className="p-5 bg-slate-950 border border-slate-700 rounded-lg">
                                                <div className="flex items-center gap-2 mb-3">
                                                    <MapPin className="w-5 h-5 text-cyan-400" />
                                                    <div className="text-sm font-mono text-slate-400 uppercase tracking-wider">Location</div>
                                                </div>
                                                <div className="space-y-2">
                                                    <div>
                                                        <div className="text-xs text-slate-500 mb-0.5">Country</div>
                                                        <div className="text-white font-medium">{ipLookupResult.country || 'Unknown'}</div>
                                                    </div>
                                                    {ipLookupResult.city && (
                                                        <div>
                                                            <div className="text-xs text-slate-500 mb-0.5">City</div>
                                                            <div className="text-white font-medium">{ipLookupResult.city}</div>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>

                                            {/* Network Info */}
                                            <div className="p-5 bg-slate-950 border border-slate-700 rounded-lg">
                                                <div className="flex items-center gap-2 mb-3">
                                                    <Globe className="w-5 h-5 text-cyan-400" />
                                                    <div className="text-sm font-mono text-slate-400 uppercase tracking-wider">Network</div>
                                                </div>
                                                <div>
                                                    <div className="text-xs text-slate-500 mb-0.5">ASN</div>
                                                    <div className="text-white font-medium font-mono text-sm">{ipLookupResult.asn || 'Unknown'}</div>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Categories */}
                                        {ipLookupResult.categories && ipLookupResult.categories.length > 0 && (
                                            <div className="p-5 bg-slate-950 border border-slate-700 rounded-lg">
                                                <div className="flex items-center gap-2 mb-3">
                                                    <AlertTriangle className="w-5 h-5 text-orange-400" />
                                                    <div className="text-sm font-mono text-slate-400 uppercase tracking-wider">Threat Categories</div>
                                                </div>
                                                <div className="flex flex-wrap gap-2">
                                                    {ipLookupResult.categories.map((category, idx) => (
                                                        <span key={idx} className="px-3 py-1.5 bg-orange-500/20 border border-orange-500/50 rounded-lg text-orange-300 text-sm font-medium">
                                                            {category}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {/* Data Sources */}
                                        <div className="p-5 bg-slate-950 border border-slate-700 rounded-lg">
                                            <div className="flex items-center gap-2 mb-3">
                                                <Database className="w-5 h-5 text-purple-400" />
                                                <div className="text-sm font-mono text-slate-400 uppercase tracking-wider">Data Sources</div>
                                            </div>
                                            <div className="flex flex-wrap gap-2">
                                                {ipLookupResult.sources && ipLookupResult.sources.length > 0 ? (
                                                    ipLookupResult.sources.map((source, idx) => (
                                                        <span key={idx} className="px-3 py-1.5 bg-purple-500/20 border border-purple-500/50 rounded-lg text-purple-300 text-sm font-medium">
                                                            {source}
                                                        </span>
                                                    ))
                                                ) : (
                                                    <span className="text-slate-500 text-sm">No sources available</span>
                                                )}
                                            </div>
                                            {ipLookupResult.cache_hit && (
                                                <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
                                                    <Info className="w-3 h-3" />
                                                    <span>Cached result</span>
                                                </div>
                                            )}
                                        </div>

                                        {/* Last Seen */}
                                        {ipLookupResult.last_seen && (
                                            <div className="p-5 bg-slate-950 border border-slate-700 rounded-lg">
                                                <div className="flex items-center gap-2 mb-3">
                                                    <Clock className="w-5 h-5 text-cyan-400" />
                                                    <div className="text-sm font-mono text-slate-400 uppercase tracking-wider">Last Seen</div>
                                                </div>
                                                <div className="text-white font-mono">{new Date(ipLookupResult.last_seen).toLocaleString()}</div>
                                            </div>
                                        )}

                                        {/* External Reports */}
                                        <div className="p-5 bg-gradient-to-br from-slate-950 to-slate-900 border border-cyan-500/30 rounded-lg">
                                            <div className="flex items-center gap-2 mb-4">
                                                <Eye className="w-5 h-5 text-cyan-400" />
                                                <div className="text-sm font-mono text-slate-400 uppercase tracking-wider">External Reports</div>
                                            </div>
                                            <div className="space-y-3">
                                                {/* VirusTotal */}
                                                <a
                                                    href={`https://www.virustotal.com/gui/ip-address/${ipLookupResult.ip}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center justify-between p-3 bg-slate-900/50 hover:bg-slate-800 border border-slate-700 hover:border-blue-500/50 rounded-lg transition-all group"
                                                >
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-10 h-10 bg-blue-500/20 border border-blue-500/50 rounded-lg flex items-center justify-center">
                                                            <Shield className="w-5 h-5 text-blue-400" />
                                                        </div>
                                                        <div>
                                                            <div className="text-white font-semibold group-hover:text-blue-400 transition-colors">
                                                                VirusTotal
                                                            </div>
                                                            <div className="text-xs text-slate-400">
                                                                View detailed malware analysis and detection report
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
                                                </a>

                                                {/* AbuseIPDB */}
                                                <a
                                                    href={`https://www.abuseipdb.com/check/${ipLookupResult.ip}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center justify-between p-3 bg-slate-900/50 hover:bg-slate-800 border border-slate-700 hover:border-orange-500/50 rounded-lg transition-all group"
                                                >
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-10 h-10 bg-orange-500/20 border border-orange-500/50 rounded-lg flex items-center justify-center">
                                                            <AlertTriangle className="w-5 h-5 text-orange-400" />
                                                        </div>
                                                        <div>
                                                            <div className="text-white font-semibold group-hover:text-orange-400 transition-colors">
                                                                AbuseIPDB
                                                            </div>
                                                            <div className="text-xs text-slate-400">
                                                                Check abuse reports and confidence score
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-orange-400 group-hover:translate-x-1 transition-all" />
                                                </a>

                                                {/* AlienVault OTX */}
                                                <a
                                                    href={`https://otx.alienvault.com/indicator/ip/${ipLookupResult.ip}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center justify-between p-3 bg-slate-900/50 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500/50 rounded-lg transition-all group"
                                                >
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-10 h-10 bg-cyan-500/20 border border-cyan-500/50 rounded-lg flex items-center justify-center">
                                                            <Globe className="w-5 h-5 text-cyan-400" />
                                                        </div>
                                                        <div>
                                                            <div className="text-white font-semibold group-hover:text-cyan-400 transition-colors">
                                                                AlienVault OTX
                                                            </div>
                                                            <div className="text-xs text-slate-400">
                                                                View threat intelligence pulses and IOCs
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                                                </a>

                                                {/* Shodan */}
                                                <a
                                                    href={`https://www.shodan.io/host/${ipLookupResult.ip}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center justify-between p-3 bg-slate-900/50 hover:bg-slate-800 border border-slate-700 hover:border-purple-500/50 rounded-lg transition-all group"
                                                >
                                                    <div className="flex items-center gap-3">
                                                        <div className="w-10 h-10 bg-purple-500/20 border border-purple-500/50 rounded-lg flex items-center justify-center">
                                                            <Search className="w-5 h-5 text-purple-400" />
                                                        </div>
                                                        <div>
                                                            <div className="text-white font-semibold group-hover:text-purple-400 transition-colors">
                                                                Shodan
                                                            </div>
                                                            <div className="text-xs text-slate-400">
                                                                Discover open ports and exposed services
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-1 transition-all" />
                                                </a>
                                            </div>
                                            <div className="mt-4 pt-3 border-t border-slate-700 flex items-center gap-2 text-xs text-slate-500">
                                                <Info className="w-3 h-3" />
                                                <span>Links open in new tab for deeper analysis</span>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Malicious IP Reference List */}
                            <div className="mt-6 bg-gradient-to-br from-slate-900 to-slate-800 border border-red-500/30 rounded-xl p-6 shadow-2xl">
                                {/* Header with Refresh */}
                                <div className="flex items-center justify-between mb-6">
                                    <div className="flex items-center gap-3">
                                        <AlertTriangle className="w-6 h-6 text-red-400" />
                                        <div>
                                            <h3 className="text-2xl font-bold text-white">Active Malicious IPs</h3>
                                            <p className="text-sm text-slate-400">
                                                Click any IP to test the lookup tool
                                                {lastUpdated && (
                                                    <span className="ml-2 text-xs text-slate-500">
                                                        • Updated {new Date(lastUpdated).toLocaleTimeString()}
                                                    </span>
                                                )}
                                            </p>
                                        </div>
                                    </div>
                                    <button
                                        onClick={fetchMaliciousIPs}
                                        disabled={ipListLoading}
                                        className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/50 rounded-lg text-cyan-400 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                                        title="Refresh malicious IP list"
                                    >
                                        <RefreshCw className={`w-4 h-4 ${ipListLoading ? 'animate-spin' : ''}`} />
                                        <span className="text-sm font-medium">Refresh</span>
                                    </button>
                                </div>

                                {/* Loading State */}
                                {ipListLoading && maliciousIPList.length === 0 && (
                                    <div className="flex items-center justify-center py-12">
                                        <div className="flex items-center gap-3 text-slate-400">
                                            <RefreshCw className="w-5 h-5 animate-spin" />
                                            <span>Loading malicious IPs from threat feeds...</span>
                                        </div>
                                    </div>
                                )}

                                {/* Active IPs Grid */}
                                {maliciousIPList.length > 0 && (
                                    <>
                                        <div className="mb-4">
                                            <div className="flex items-center gap-2 mb-3">
                                                <div className="w-1 h-5 bg-red-500 rounded"></div>
                                                <span className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                                                    Recently Active ({maliciousIPList.length})
                                                </span>
                                                <span className="text-xs text-slate-500">Last 7 days</span>
                                            </div>
                                        </div>

                                        <div className="grid md:grid-cols-2 gap-4 mb-6">
                                            {maliciousIPList.map((item, idx) => {
                                                const severityColors = {
                                                    critical: { bg: 'bg-red-500/10', border: 'border-red-500/50', text: 'text-red-400', badge: 'bg-red-500/20 border-red-500' },
                                                    high: { bg: 'bg-orange-500/10', border: 'border-orange-500/50', text: 'text-orange-400', badge: 'bg-orange-500/20 border-orange-500' },
                                                    medium: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/50', text: 'text-yellow-400', badge: 'bg-yellow-500/20 border-yellow-500' },
                                                    low: { bg: 'bg-blue-500/10', border: 'border-blue-500/50', text: 'text-blue-400', badge: 'bg-blue-500/20 border-blue-500' }
                                                };
                                                const colors = severityColors[item.severity] || severityColors.medium;

                                                return (
                                                    <button
                                                        key={idx}
                                                        onClick={() => {
                                                            setIpSearchQuery(item.ip);
                                                            handleIPLookup(item.ip);
                                                        }}
                                                        className={`p-5 ${colors.bg} border ${colors.border} rounded-lg text-left hover:scale-[1.02] transition-all group relative overflow-hidden`}
                                                    >
                                                        {/* New Badge */}
                                                        {new Date(item.lastSeen) > new Date(Date.now() - 24 * 60 * 60 * 1000) && (
                                                            <div className="absolute top-2 right-2">
                                                                <span className="px-2 py-0.5 bg-green-500/20 border border-green-500 rounded text-xs text-green-400 font-bold animate-pulse">
                                                                    NEW
                                                                </span>
                                                            </div>
                                                        )}

                                                        <div className="flex items-start justify-between mb-3">
                                                            <div className="flex items-center gap-2">
                                                                <Globe className={`w-5 h-5 ${colors.text}`} />
                                                                <code className={`text-lg font-bold font-mono ${colors.text}`}>
                                                                    {item.ip}
                                                                </code>
                                                            </div>
                                                            <span className={`px-2 py-1 ${colors.badge} border rounded text-xs font-bold uppercase`}>
                                                                {item.severity}
                                                            </span>
                                                        </div>

                                                        <p className="text-sm text-slate-300 mb-3 leading-relaxed">
                                                            {item.description}
                                                        </p>

                                                        <div className="flex flex-wrap gap-2 mb-3">
                                                            {item.threatTypes.map((type, typeIdx) => (
                                                                <span
                                                                    key={typeIdx}
                                                                    className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-400 font-mono"
                                                                >
                                                                    {type}
                                                                </span>
                                                            ))}
                                                        </div>

                                                        <div className="flex items-center justify-between text-xs text-slate-500">
                                                            <div className="flex items-center gap-1">
                                                                <Clock className="w-3 h-3" />
                                                                <span>
                                                                    {new Date(item.lastSeen).toLocaleDateString()}
                                                                </span>
                                                            </div>
                                                            <div className={`flex items-center gap-1 ${colors.text} opacity-0 group-hover:opacity-100 transition-opacity`}>
                                                                <Search className="w-3 h-3" />
                                                                <span className="font-medium">Click to lookup</span>
                                                            </div>
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </>
                                )}

                                {/* Archived IPs Section */}
                                {archivedIPList.length > 0 && (
                                    <div className="border-t border-slate-700 pt-6">
                                        <button
                                            onClick={() => setShowArchived(!showArchived)}
                                            className="flex items-center justify-between w-full mb-4 group"
                                        >
                                            <div className="flex items-center gap-2">
                                                <Database className="w-5 h-5 text-slate-400" />
                                                <span className="text-lg font-semibold text-slate-300">
                                                    Archived IPs ({archivedIPList.length})
                                                </span>
                                                <span className="text-xs text-slate-500">Older than 7 days</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-cyan-400 group-hover:text-cyan-300">
                                                <span className="text-sm">
                                                    {showArchived ? 'Hide' : 'Show'}
                                                </span>
                                                <ChevronRight className={`w-4 h-4 transition-transform ${showArchived ? 'rotate-90' : ''}`} />
                                            </div>
                                        </button>

                                        {showArchived && (
                                            <div className="grid md:grid-cols-3 gap-3 animate-fadeIn">
                                                {archivedIPList.map((item, idx) => {
                                                    const severityColors = {
                                                        critical: { bg: 'bg-red-500/5', border: 'border-red-500/30', text: 'text-red-400' },
                                                        high: { bg: 'bg-orange-500/5', border: 'border-orange-500/30', text: 'text-orange-400' },
                                                        medium: { bg: 'bg-yellow-500/5', border: 'border-yellow-500/30', text: 'text-yellow-400' },
                                                        low: { bg: 'bg-blue-500/5', border: 'border-blue-500/30', text: 'text-blue-400' }
                                                    };
                                                    const colors = severityColors[item.severity] || severityColors.low;

                                                    return (
                                                        <button
                                                            key={idx}
                                                            onClick={() => {
                                                                setIpSearchQuery(item.ip);
                                                                handleIPLookup(item.ip);
                                                            }}
                                                            className={`p-3 ${colors.bg} border ${colors.border} rounded-lg text-left hover:bg-slate-800/50 transition-all group`}
                                                        >
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <code className={`text-sm font-bold font-mono ${colors.text}`}>
                                                                    {item.ip}
                                                                </code>
                                                            </div>
                                                            <p className="text-xs text-slate-400 mb-2 line-clamp-2">
                                                                {item.description}
                                                            </p>
                                                            <div className="flex items-center justify-between text-xs">
                                                                <span className="text-slate-500">
                                                                    {new Date(item.lastSeen).toLocaleDateString()}
                                                                </span>
                                                                <span className={`${colors.text} opacity-0 group-hover:opacity-100 text-xs`}>
                                                                    Lookup →
                                                                </span>
                                                            </div>
                                                        </button>
                                                    );
                                                })}
                                            </div>
                                        )}
                                    </div>
                                )}

                                {/* Info Panel */}
                                <div className="mt-6 p-4 bg-slate-950 border border-slate-700 rounded-lg">
                                    <div className="flex items-start gap-3">
                                        <Info className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                                        <div className="text-sm text-slate-300">
                                            <p className="font-semibold text-blue-400 mb-1">About This List</p>
                                            <p>
                                                Malicious IPs are automatically updated from live threat intelligence feeds.
                                                Active IPs (last 7 days) appear above, while older IPs are archived below.
                                                The list refreshes hourly and can be manually refreshed using the button above.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'malware' && (
                        <div className="max-w-5xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <AlertTriangle className="w-6 h-6 text-orange-400" />
                                    URLhaus Malware Distribution URLs
                                </h3>

                                <div className="space-y-4">
                                    {(threatData.malwareUrls || []).map((threat, idx) => (
                                        <div key={threat.id || idx} className="p-6 bg-slate-950 border border-slate-700 rounded-lg hover:border-orange-500/50 transition-all">
                                            <div className="flex items-start justify-between mb-3">
                                                <div className="flex-1">
                                                    {/* Header with Severity Badge */}
                                                    <div className="flex items-center gap-3 mb-3">
                                                        <span className={`px-3 py-1 rounded text-xs font-bold uppercase border ${getSeverityColor(threat.severity)}`}>
                                                            {threat.severity || 'medium'}
                                                        </span>
                                                        <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-orange-400 font-mono">
                                                            {threat.type}
                                                        </span>
                                                        {threat.source && (
                                                            <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-purple-400 font-mono">
                                                                {threat.source}
                                                            </span>
                                                        )}
                                                        {threat.timestamp && (
                                                            <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-slate-400 font-mono flex items-center gap-1">
                                                                <Clock className="w-3 h-3" />
                                                                {formatTimestamp(threat.timestamp)}
                                                            </span>
                                                        )}
                                                    </div>

                                                    {/* Threat Name */}
                                                    <div className="text-white font-semibold mb-2">{threat.name}</div>

                                                    {/* Description */}
                                                    {threat.description && (
                                                        <div className="text-slate-300 text-sm mb-3 pl-3 border-l-2 border-orange-500/50">
                                                            {threat.description}
                                                        </div>
                                                    )}

                                                    {/* Malicious URLs Display */}
                                                    {threat.indicators && threat.indicators.length > 0 && (
                                                        <div className="mb-4">
                                                            <div className="text-xs text-slate-500 mb-2 uppercase tracking-wider font-mono">
                                                                Malicious URL{threat.indicators.length > 1 ? 's' : ''} ({threat.indicators.length})
                                                            </div>
                                                            <div className="space-y-2">
                                                                {threat.indicators.map((url, i) => (
                                                                    <code key={i} className="block p-3 bg-slate-900 border border-red-500/30 rounded text-sm text-red-300 font-mono break-all">
                                                                        {url}
                                                                    </code>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Details Grid */}
                                                    <div className="grid md:grid-cols-3 gap-4 mb-4">
                                                        {threat.countries && threat.countries.length > 0 && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Affected Regions</div>
                                                                <div className="flex flex-wrap gap-2">
                                                                    {threat.countries.map((country, i) => (
                                                                        <span key={i} className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 flex items-center gap-1">
                                                                            <MapPin className="w-3 h-3 text-red-400" />
                                                                            {country}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        )}

                                                        {threat.id && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">URLhaus ID</div>
                                                                <div className="text-sm text-cyan-400 font-mono">{threat.id.replace('urlhaus_', '')}</div>
                                                            </div>
                                                        )}

                                                        {threat.timestamp && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">First Seen</div>
                                                                <div className="text-sm text-slate-300 flex items-center gap-2">
                                                                    <Clock className="w-4 h-4 text-orange-400" />
                                                                    {formatTimestamp(threat.timestamp)}
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>

                                                    {/* URLhaus Link */}
                                                    {threat.id && (
                                                        <a
                                                            href={`https://urlhaus.abuse.ch/url/${threat.id.replace('urlhaus_', '')}/`}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="inline-flex items-center gap-2 px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 text-orange-300 border border-orange-500/50 rounded-lg text-sm font-medium transition-all hover:border-orange-400">
                                                            <Globe className="w-4 h-4" />
                                                            View on URLhaus
                                                            <ArrowRight className="w-4 h-4" />
                                                        </a>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'c2' && (
                        <div className="max-w-5xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <Globe className="w-6 h-6 text-red-400" />
                                    Feodo Tracker C2 Infrastructure
                                </h3>

                                <div className="space-y-4">
                                    {(threatData.c2Servers || []).map((server, idx) => (
                                        <div key={server.id || idx} className="p-6 bg-slate-950 border border-slate-700 rounded-lg hover:border-red-500/50 transition-all">
                                            <div className="flex items-start justify-between mb-3">
                                                <div className="flex-1">
                                                    {/* Header with Severity Badge */}
                                                    <div className="flex items-center gap-3 mb-3">
                                                        <span className={`px-3 py-1 rounded text-xs font-bold uppercase border ${getSeverityColor(server.severity)}`}>
                                                            {server.severity || 'critical'}
                                                        </span>
                                                        <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-red-400 font-mono">
                                                            {server.type}
                                                        </span>
                                                        {server.timestamp && (
                                                            <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-slate-400 font-mono flex items-center gap-1">
                                                                <Clock className="w-3 h-3" />
                                                                {formatTimestamp(server.timestamp)}
                                                            </span>
                                                        )}
                                                    </div>

                                                    {/* Server Name */}
                                                    <div className="text-white font-semibold mb-3">{server.name}</div>

                                                    {/* Server Details Grid */}
                                                    <div className="grid md:grid-cols-3 gap-4 mb-4">
                                                        {server.ipAddress && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">IP Address</div>
                                                                <code className="text-sm text-cyan-400 font-mono">{server.ipAddress}</code>
                                                            </div>
                                                        )}
                                                        {server.port && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Port</div>
                                                                <code className="text-sm text-slate-300 font-mono">{server.port}</code>
                                                            </div>
                                                        )}
                                                        {server.country && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Location</div>
                                                                <div className="text-sm text-slate-300 flex items-center gap-1">
                                                                    <MapPin className="w-3 h-3 text-red-400" />
                                                                    {server.country}
                                                                </div>
                                                            </div>
                                                        )}
                                                        {server.malwareFamily && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Malware Family</div>
                                                                <div className="text-sm text-slate-300">{server.malwareFamily}</div>
                                                            </div>
                                                        )}
                                                        {server.status && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Status</div>
                                                                <span className={`px-2 py-1 rounded text-xs font-medium ${server.status === 'online' ? 'bg-red-500/20 text-red-400' :
                                                                    'bg-slate-700 text-slate-400'
                                                                    }`}>
                                                                    {server.status}
                                                                </span>
                                                            </div>
                                                        )}
                                                        {server.lastSeen && (
                                                            <div>
                                                                <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Last Seen</div>
                                                                <div className="text-sm text-slate-300">{formatTimestamp(server.lastSeen)}</div>
                                                            </div>
                                                        )}
                                                    </div>

                                                    {/* Description */}
                                                    {server.description && (
                                                        <div className="text-slate-300 text-sm leading-relaxed pl-3 border-l-2 border-red-500/50">
                                                            {server.description}
                                                        </div>
                                                    )}
                                                </div>
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
                                    Recent Critical Vulnerabilities (Last 7 Days)
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
                                                    <div className="text-white font-semibold mb-3">{vuln.product}</div>

                                                    {/* Full Description */}
                                                    <div className="text-slate-300 text-sm leading-relaxed mb-4 pl-3 border-l-2 border-slate-700">
                                                        {vuln.description}
                                                    </div>

                                                    {/* NVD Link */}
                                                    {vuln.nvd_link && (
                                                        <a
                                                            href={vuln.nvd_link}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 border border-blue-500/50 rounded-lg text-sm font-medium transition-all hover:border-blue-400"
                                                        >
                                                            <Globe className="w-4 h-4" />
                                                            View on NVD
                                                            <ArrowRight className="w-4 h-4" />
                                                        </a>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'intelligence' && (
                        <div className="max-w-5xl mx-auto">
                            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-xl p-8">
                                <h3 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
                                    <Database className="w-6 h-6 text-cyan-400" />
                                    AlienVault OTX Threat Intelligence Pulses
                                </h3>

                                <div className="space-y-4">
                                    {(threatData.otxIntelligence || []).map((pulse, idx) => {
                                        // Extract OTX pulse ID from the id field (format: otx_PULSEID)
                                        const pulseId = pulse.id ? pulse.id.replace('otx_', '') : '';
                                        const otxUrl = pulseId ? `https://otx.alienvault.com/pulse/${pulseId}` : null;

                                        return (
                                            <div key={pulse.id || idx} className="p-6 bg-slate-950 border border-slate-700 rounded-lg hover:border-cyan-500/50 transition-all group">
                                                <div className="flex items-start justify-between mb-3">
                                                    <div className="flex-1">
                                                        {/* Header with Severity Badge */}
                                                        <div className="flex items-center gap-3 mb-3">
                                                            <span className={`px-3 py-1 rounded text-xs font-bold uppercase border ${getSeverityColor(pulse.severity)}`}>
                                                                {pulse.severity || 'medium'}
                                                            </span>
                                                            <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-cyan-400 font-mono">
                                                                {pulse.type || 'Threat Intelligence'}
                                                            </span>
                                                            {pulse.source && (
                                                                <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-purple-400 font-mono">
                                                                    {pulse.source}
                                                                </span>
                                                            )}
                                                            {pulse.timestamp && (
                                                                <span className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-sm text-slate-400 font-mono flex items-center gap-1">
                                                                    <Clock className="w-3 h-3" />
                                                                    {formatTimestamp(pulse.timestamp)}
                                                                </span>
                                                            )}
                                                        </div>

                                                        {/* Pulse Name */}
                                                        <div className="text-white font-semibold mb-3">{pulse.name}</div>

                                                        {/* Full Description */}
                                                        {pulse.description && (
                                                            <div className="text-slate-300 text-sm leading-relaxed mb-4 pl-3 border-l-2 border-slate-700">
                                                                {pulse.description}
                                                            </div>
                                                        )}

                                                        {/* Key Details Grid */}
                                                        <div className="grid md:grid-cols-2 gap-4 mb-4">
                                                            {pulse.source && (
                                                                <div>
                                                                    <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Source</div>
                                                                    <div className="text-sm text-slate-300">{pulse.source}</div>
                                                                </div>
                                                            )}
                                                            {pulse.timestamp && (
                                                                <div>
                                                                    <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Published</div>
                                                                    <div className="text-sm text-slate-300 flex items-center gap-2">
                                                                        <Clock className="w-4 h-4 text-cyan-400" />
                                                                        {formatTimestamp(pulse.timestamp)}
                                                                    </div>
                                                                </div>
                                                            )}
                                                            {pulse.countries && pulse.countries.length > 0 && (
                                                                <div className="md:col-span-2">
                                                                    <div className="text-xs text-slate-500 mb-1 uppercase tracking-wider font-mono">Targeted Countries</div>
                                                                    <div className="flex flex-wrap gap-2">
                                                                        {pulse.countries.map((country, i) => (
                                                                            <span key={i} className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 flex items-center gap-1">
                                                                                <MapPin className="w-3 h-3 text-cyan-400" />
                                                                                {country}
                                                                            </span>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>

                                                        {/* Indicators (if available) */}
                                                        {pulse.indicators && pulse.indicators.length > 0 && (
                                                            <div className="mb-4">
                                                                <div className="text-xs text-slate-500 mb-2 uppercase tracking-wider font-mono">
                                                                    Indicators of Compromise ({pulse.indicators.length})
                                                                </div>
                                                                <div className="grid md:grid-cols-2 gap-2">
                                                                    {pulse.indicators.map((indicator, i) => (
                                                                        <code key={i} className="px-3 py-2 bg-slate-900 border border-cyan-500/30 rounded text-xs text-cyan-300 font-mono break-all">
                                                                            {indicator}
                                                                        </code>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        )}

                                                        {/* OTX Link */}
                                                        {otxUrl && (
                                                            <a
                                                                href={otxUrl}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 rounded-lg text-sm font-medium transition-all hover:border-cyan-400"
                                                            >
                                                                <Globe className="w-4 h-4" />
                                                                View on AlienVault OTX
                                                                <ArrowRight className="w-4 h-4" />
                                                            </a>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};