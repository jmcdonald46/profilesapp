// Filename - App.js

import React from "react";
import "./app.css";
import logo from './pictures/photo.jpg'

function App() {
    return (
        <div>
            <nav class="navbar background">
                <ul class="nav-list">
                    <div class="logo">
                        <img src={logo} alt="logo"/>
                    </div>
                    <li>
                        <a href="#home">Home</a>
                    </li>
                    <li>
                        <a href="#about">About</a>
                    </li>
                    <li>
                        <a href="services">Portfolio</a>
                    </li>
  
                </ul>

                <div class="rightNav">
                    <input
                        type="text"
                        name="search"
                        id="search"
                    />
                    <button class="btn btn-sm">
                        Search
                    </button>
                </div>
            </nav>

            <section class="section">
                <div class="box-main">
                    <div class="firstHalf">
                        <h1 class="text-big">
                            Jordan McDonald
                        </h1>
                        <p class="text-small">
                            Hello! Welcome to my page, my name is Jordan McDonald and I am B.S. Major of Cybersecurity looking for my next chance
                            to dive deep into solving problems and invent new solutions to deliver customer results. I pride myself on being 
                            a motivated, persistent, natural leader and I am ready to apply a great work ethic to find new ways to innovate for
                            all stakeholders. Thank you for visiting my page!
                        </p>
                    </div>
                </div>
            </section>
            <section class="section">
                <div class="box-main">
                    <div class="secondHalf">
                        <h1 class="text-big" id="program">
                            
                        </h1>
                        <p class="text-small">
                            
                        </p>
                    </div>
                </div>
            </section>
            <section class="section">
                <div class="box-main">
                    <div class="secondHalf">
                        <h1 class="text-big" id="program">
                            
                        </h1>
                        <p class="text-small">
                            
                        </p>
                    </div>
                </div>
            </section>
            <section class="section">
                <div class="box-main">
                    <div class="secondHalf">
                        <h1 class="text-big" id="program">
                            
                        </h1>
                        <p class="text-small">
                            
                        </p>
                    </div>
                </div>
            </section>
            <footer className="footer">
                <p className="text-footer">
                    Copyright ©-All rights are reserved
                </p>
            </footer>
        </div>
    );
}

export default App;