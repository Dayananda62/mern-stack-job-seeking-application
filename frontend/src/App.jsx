import React, { useEffect,useContext } from "react";
import "./App.css";
import { Context } from "./main.jsx";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from "./components/Auth/Login.jsx";
import Register from "./components/Auth/Register.jsx";
import NavBar from "./components/Layout/Navbar.jsx";
import Footer from "./components/Layout/Footer.jsx";
import Home from "./components/Home/Home.jsx";
import Jobs from "./components/Job/Jobs.jsx";
import JobDetails from "./components/Job/JobDetails.jsx";
import MyJobs from "./components/Job/MyJobs.jsx";
import PostJob from "./components/Job/PostJob.jsx";
import Application from "./components/Application/Application.jsx";
import MyApplications from "./components/Application/MyApplications.jsx";
import NotFound from "./components/NotFound/NotFound.jsx";
import axios from "axios";
import { Toaster } from "react-hot-toast";

const App = () => {

  const { isAuthorized, setIsAuthorized, setUser } = useContext(Context);
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await axios.get(
          "http://localhost:4000/api/v1/user/getuser",
          {
            withCredentials: true,
          }
        );
        setUser(response.data.user);
        setIsAuthorized(true);
      } catch (error) {
        setIsAuthorized(false);
      }
    };
    fetchUser();
  }, [isAuthorized]);


  return (
    <>
      <Router>
        <NavBar />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/" element={<Home />} />
          <Route path="/job/getall" element={<Jobs />} />
          <Route path="/job/:id" element={<JobDetails />} />
          <Route path="/application/:id" element={<Application />} />
          <Route path="/applications/me" element={<MyApplications />} />
          <Route path="/job/post" element={<PostJob />} />
          <Route path="/job/me" element={<MyJobs />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
        <Footer />
        <Toaster/>
      </Router>
    </>
  );
};

export default App;
