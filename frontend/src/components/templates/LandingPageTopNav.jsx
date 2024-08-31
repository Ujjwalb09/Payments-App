import React, { useState } from "react";
import { NavLink, useLocation, useNavigate, useParams } from "react-router-dom";
import { Link } from "react-router-dom";

const LandingPageTopNav = ({ btnText }) => {
  const [loading, setLoading] = useState(false);
  const [home, setHome] = useState(false);
  const [contactUs, setContactUs] = useState(false);
  const [about, setAbout] = useState(false);
  const navigate = useNavigate();

  const { pathname } = useLocation();
  console.log(typeof pathname.split("/")[1]);

  return (
    <div className="TOPNAV w-full h-[9vh] flex justify-between border-gray-200 items-center relative z-50 bg-white shadow-md">
      <div className="pl-[6rem] pb-1">
        <Link to={"/"}>
          <img className="h-20" src="../../assets/payzip.png" alt="" />
        </Link>
      </div>

      <div className="flex justify-between items-center w-[44%]">
        <div className="flex gap-[7rem] font-semibold font-raleway">
          <NavLink
            className={(e) => {
              return [
                e.isActive ? "font-bold scale-110" : "",
                "hover:scale-105",
              ].join(" ");
            }}
            to={"/"}
          >
            Home
          </NavLink>
          <NavLink
            className={(e) => {
              return [
                e.isActive ? "font-bold scale-110" : "",
                "hover:scale-105",
              ].join(" ");
            }}
            to={"/contactUs"}
          >
            Contact Us
          </NavLink>
          <NavLink
          // className={(e) => {
          //   return [
          //     e.isActive ? "font-bold scale-110" : "",
          //     "hover:scale-105",
          //   ].join(" ");
          // }}
          >
            About
          </NavLink>
        </div>
        <button
          onClick={() => {
            setLoading(true);
            setTimeout(() => {
              btnText === "Sign Up" ? navigate("/signup") : navigate("/signin");
            }, 1000);
          }}
          className="w-[8rem] bg-black mr-32 text-white py-[0.4rem] rounded-3xl hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 hover:scale-105 font-raleway text-lg duration-200"
        >
          {loading ? (
            <img
              className="w-full h-6 animate-spin ease-linear"
              src="../assets/loading.svg"
              alt="Loading icon"
            ></img>
          ) : (
            btnText
          )}
        </button>
      </div>
    </div>
  );
};

export default LandingPageTopNav;
