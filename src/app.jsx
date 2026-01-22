import React, { useState, useEffect } from 'react';
import { Github, Linkedin, Mail, ArrowRight, Code, CloudCheck, GraduationCap, Palette, Zap, X } from 'lucide-react';
import profileImage from '/public/IMGpfp.jpeg';

export default function App() {
    const [scrollY, setScrollY] = useState(0);
    const [showDocument, setShowDocument] = useState(false);
    const [pdfError, setPdfError] = useState(false);
    const [isMobile, setIsMobile] = useState(false);

    // Your Google Drive sharing link
    const googleDocUrl = 'https://drive.google.com/file/d/1L7QnVHeVyMD6w9E5lS_MuRoc3Fns5ru7/view?usp=sharing';

    // Convert to embeddable URL for iframe
    const documentUrl = googleDocUrl.replace('/view?usp=sharing', '/preview');

    useEffect(() => {
        const handleScroll = () => setScrollY(window.scrollY);
        window.addEventListener('scroll', handleScroll);

        // Detect mobile device
        const checkMobile = () => {
            setIsMobile(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent));
        };
        checkMobile();

        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const projects = [
        {
            title: "Jordan McDonald Resumé",
            description: "View My Resumé Here",
            tech: ["1.5yrs Amazon L4", "Leadership Role", "Cyber Degree"],
            gradient: "from-blue-500 to-cyan-500",
            showPreview: true,
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
            title: "Work In Progress",
            description: "",
            tech: [""],
            gradient: "from-purple-500 to-pink-500"
        },
        {
            title: "Work In Progress",
            description: "",
            tech: [""],
            gradient: "from-orange-500 to-red-500"
        }
    ];

    const skills = [
        {
            name: "AWS Cloud Certified",
            icon: CloudCheck,
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
            {/* Document Modal Overlay */}
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
                        {isMobile ? (
                            <div className="w-full flex-1 flex flex-col items-center justify-center p-4 md:p-8 text-center">
                                <Code className="w-16 h-16 md:w-20 md:h-20 text-cyan-400 mb-4 md:mb-6" />
                                <h3 className="text-xl md:text-2xl font-bold mb-3 md:mb-4">View Resume</h3>
                                <p className="text-sm md:text-base text-slate-300 mb-6 md:mb-8 max-w-md">
                                    For the best viewing experience on mobile, please open the resume in a new tab.
                                </p>
                                <a
                                    href={googleDocUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="bg-cyan-500 hover:bg-cyan-600 text-white font-semibold px-6 py-3 md:px-8 md:py-4 rounded-lg transition shadow-lg hover:shadow-cyan-500/50 inline-flex items-center gap-2 text-sm md:text-base"
                                >
                                    <ArrowRight className="w-4 h-4 md:w-5 md:h-5" />
                                    Open Resume
                                </a>
                            </div>
                        ) : !pdfError ? (
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
                        {!isMobile && !pdfError && (
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

            {/* Navigation */}
            <nav className="fixed top-0 w-full bg-slate-900/80 backdrop-blur-md z-50 border-b border-slate-700/50">
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
                <div className="max-w-6xl mx-auto w-full">
                    <div className="grid md:grid-cols-2 gap-8 md:gap-12 items-center">
                        {/* Left Column - Text Content */}
                        <div
                            className="transition-all duration-700"
                            style={{
                                opacity: 1 - scrollY / 500,
                                transform: `translateY(${scrollY * 0.3}px)`
                            }}
                        >
                            <h2 className="text-5xl md:text-6xl lg:text-7xl font-bold mb-4 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent leading-tight pb-2">
                                Aspiring Cloud Engineer
                            </h2>
                            <p className="text-lg md:text-xl lg:text-2xl text-slate-300 mb-8">
                                Staying Curious, Adapting to Change, Relentlessly Driven
                            </p>
                            <div className="flex gap-4 mb-8">
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

                        {/* Right Column - Image */}
                        <div
                            className="transition-all duration-700"
                            style={{
                                opacity: 1 - scrollY / 500,
                                transform: `translateY(${scrollY * 0.3}px)`
                            }}
                        >
                            <div className="relative w-full aspect-square max-w-md mx-auto">
                                <div className="w-full h-full rounded-2xl bg-gradient-to-br from-cyan-500/20 via-blue-500/20 to-purple-600/20 backdrop-blur-sm border border-slate-700/50 flex items-center justify-center overflow-hidden">
                                    <img
                                        src={profileImage}
                                        alt="Jordan McDonald"
                                        className="w-full h-full object-cover"
                                    />
                                </div>
                                <div className="absolute -inset-4 bg-gradient-to-r from-cyan-500/10 to-purple-600/10 rounded-2xl blur-2xl -z-10"></div>
                            </div>
                        </div>
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
                                    <p className="text-slate-400">
                                        {skill.description}
                                    </p>
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
                    <div className="grid md:grid-cols-3 gap-8">
                        {projects.map((project, index) => (
                            <div
                                key={index}
                                className="bg-slate-800/50 backdrop-blur-sm rounded-2xl overflow-hidden border border-slate-700/50 hover:border-slate-600 transition-all hover:transform hover:scale-105 group"
                            >
                                {project.showPreview ? (
                                    <div className="h-48 overflow-hidden bg-slate-900 flex items-center justify-center">
                                        <div className="text-center p-6">
                                            <Code className="w-16 h-16 mx-auto mb-2 text-cyan-400" />
                                            <p className="text-slate-300 font-semibold">Jordan McDonald Resumé</p>
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
                        ))}
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
                    <p>© 2025 Jordan McDonald. Built with React 19 & Tailwind CSS v4.</p>
                </div>
            </footer>
        </div>
    );
}