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
                        <h1 class="text-big">
                            Resume 
                        </h1>
                        <div class="row">
                            <div class="columnleft"></div>
                                <div class="row">
                                <h2 class="text-big">
                                    Jordan McDonald
                                </h2>
                                </div>
                            <div class="columnright"></div>
                            <div class="row">
                                <h2 class="text-big">
                                    Objective - Cyber Security Student
                                </h2>
                            </div>
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