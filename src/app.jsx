// Filename - App.js

import React from "react";
import "./app.css";
import logo from './pictures/photo.jpg'

function App() {
    return (
        <div>
            <body>

                <div style="background:yellow;padding:5px;text-align:center;">
                    <h4>Resize the browser window to see the responsive effect.</h4>
                </div>

                <header>
                    <h1>My Website</h1>
                    <p>With a <b>flexible</b> layout.</p>
                </header>

                <div className="navbar">
                    <a href="#">Link</a>
                    <a href="#">Link</a>
                    <a href="#">Link</a>
                    <a href="#">Link</a>
                </div>

                <div className="container">
                    <div className="side">
                        <h2>About Me</h2>
                        <h5>Photo of me:</h5>
                        <div className="fakeimg" style="height:200px;">Image</div>
                        <p>Some text about me in culpa qui officia deserunt mollit anim..</p>
                        <h3>More Text</h3>
                        <p>Lorem ipsum dolor sit ame.</p>
                        <div className="fakeimg" style="height:60px;">Image</div><br />
                            <div className="fakeimg" style="height:60px;">Image</div><br />
                                <div className="fakeimg" style="height:60px;">Image</div>
                            </div>
                            <div className="main">
                                <h2>TITLE HEADING</h2>
                                <h5>Title description, Oct 7, 2025</h5>
                                <div className="fakeimg" style="height:200px;">Image</div>
                                <p>Some text..</p>
                                <p>Sunt in culpa qui officia deserunt mollit anim id est laborum consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco.</p>
                                <br />
                                    <h2>TITLE HEADING</h2>
                                    <h5>Title description, Sep 2, 2025</h5>
                                    <div className="fakeimg" style="height:200px;">Image</div>
                                    <p>Some text..</p>
                                    <p>Sunt in culpa qui officia deserunt mollit anim id est laborum consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco.</p>
                            </div>
                    </div>

                    <footer>
                        <h2>Footer</h2>
                    </footer>

            </body>
        </div>
    );
}

export default App;