import React, { useState, useEffect } from 'react';
import { Github, Linkedin, Mail, ArrowRight, Code, Palette, Zap } from 'lucide-react';

export default function App() {
    const [scrollY, setScrollY] = useState(0);

    useEffect(() => {
        const handleScroll = () => setScrollY(window.scrollY);
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const projects = [
        {
            title: "Resume",
            description: "View My Resume Here",
            tech: [""],
            gradient: "from-blue-500 to-cyan-500"
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
        { name: "AWS Cloud Certified", icon: Code, color: "text-blue-500" },
        { name: "B.S. Cybersecurity", icon: Palette, color: "text-purple-500" },
        { name: "Web Development w ReactJs", icon: Zap, color: "text-yellow-500" }
    ];

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
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
                        <h2 className="text-6xl md:text-7xl font-bold mb-4 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
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
                                        Creating innovative solutions with modern technologies and best practices.
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
                    <h3 className="text-4xl font-bold text-center mb-12">Featured Projects</h3>
                    <div className="grid md:grid-cols-3 gap-8">
                        {projects.map((project, index) => (
                            <div
                                key={index}
                                className="bg-slate-800/50 backdrop-blur-sm rounded-2xl overflow-hidden border border-slate-700/50 hover:border-slate-600 transition-all hover:transform hover:scale-105 group"
                            >
                                <div className={`h-48 bg-gradient-to-br ${project.gradient} opacity-80 group-hover:opacity-100 transition-opacity`}></div>
                                <div className="p-6">
                                    <h4 className="text-xl font-semibold mb-2">{project.title}</h4>
                                    <p className="text-slate-400 mb-4">{project.description}</p>
                                    <div className="flex flex-wrap gap-2">
                                        {project.tech.map((tech, i) => (
                                            <span key={i} className="px-3 py-1 bg-slate-700 rounded-full text-sm">
                                                {tech}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Contact Section */}
            <section id="contact" className="py-20 px-6">
                <div className="max-w-4xl mx-auto text-center">
                    <h3 className="text-4xl font-bold mb-6">Let's Work Together</h3>
                    <p className="text-xl text-slate-300 mb-8">
                        Have a project in mind? I'd love to hear about it.
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