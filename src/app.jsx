import React, { useState, useEffect } from 'react';
import { Github, Linkedin, Mail, ArrowRight, Code, Palette, Zap, X } from 'lucide-react';

export default function App() {
    const [scrollY, setScrollY] = useState(0);
    const [showDocument, setShowDocument] = useState(false);

    // FIX 1: Change the path - put PDF in public folder
    const documentUrl = './public/resume.pdf';

    useEffect(() => {
        const handleScroll = () => setScrollY(window.scrollY);
        window.addEventListener('scroll', handleScroll);
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
            icon: Code,
            color: "text-blue-500",
            description: "Working to obtain AWS Cloud certifications with emphasis on security and AI focused specialties."
        },
        {
            name: "B.S. Cybersecurity",
            icon: Palette,
            color: "text-purple-500",
            description: "Bachelor's degree in Cybersecurity with focus on network security, threat analysis, and secure system design."
        },
        {
            name: "Web Development w ReactJs",
            icon: Zap,
            color: "text-yellow-500",
            description: "Building modern, responsive web applications using React, JavaScript, and contemporary development practices."
        }
    ];

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
            {/* Document Modal Overlay */}
            {showDocument && (
                <div className="fixed inset-0 bg-black bg-opacity-90 z-50 flex items-center justify-center p-4">
                    <button
                        onClick={() => setShowDocument(false)}
                        className="fixed top-24 left-24 z-[60] bg-cyan-500 hover:bg-cyan-600 text-white font-semibold px-6 py-3 rounded-lg transition shadow-lg hover:shadow-cyan-500/50 flex items-center gap-2"
                    >
                        <X className="w-5 h-5" />
                        Close Resumé
                    </button>
                    <div className="relative w-full max-w-6xl h-full max-h-screen bg-slate-800 rounded-lg overflow-hidden">
                        {/* FIX 2: Add proper iframe attributes for cross-browser support */}
                        <iframe
                            src={`${documentUrl}#toolbar=1&navpanes=1&scrollbar=1`}
                            className="w-full h-full"
                            title="PDF Viewer"
                            type="application/pdf"
                        />
                        <div className="absolute bottom-6 left-1/2 transform -translate-x-1/2">
                            <a
                                href={documentUrl}
                                download="Jordan_McDonald_Resume.pdf"
                                className="bg-cyan-500 hover:bg-cyan-600 text-white font-semibold px-6 py-3 rounded-lg transition shadow-lg hover:shadow-cyan-500/50 inline-flex items-center gap-2"
                            >
                                <ArrowRight className="w-5 h-5 rotate-90" />
                                Download PDF
                            </a>
                        </div>
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
                <div className="max-w-4xl mx-auto text-center">
                    <div
                        className="mb-6 transition-all duration-700"
                        style={{
                            opacity: 1 - scrollY / 500,
                            transform: `translateY(${scrollY * 0.3}px)`
                        }}
                    >
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