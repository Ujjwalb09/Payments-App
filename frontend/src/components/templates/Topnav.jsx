import React, { useEffect, useState } from "react";
import { useRef } from "react";
import { Link, Outlet, useNavigate } from "react-router-dom";

const Topnav = ({ user }) => {
  const [showLogout, setShowLogout] = useState(false);
  const [loading, setLoading] = useState(false);
  const buttonContainerRef = useRef();
  const logoutBtnContainer = useRef();
  const navigate = useNavigate();
  console.log(user);

  const color = () => {
    return `rgba(${(Math.random() * 255).toFixed()}, ${(
      Math.random() * 255
    ).toFixed()}, ${(Math.random() * 255).toFixed()}, 0.4)`;
  };

  const handleClickOutside = (e) => {
    if (
      buttonContainerRef.current &&
      logoutBtnContainer.current &&
      !buttonContainerRef.current.contains(e.target) &&
      !logoutBtnContainer.current.contains(e.target)
    ) {
      setShowLogout(false);
    }
  };

  useEffect(() => {
    document.addEventListener("mousedown", handleClickOutside);

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);
  return (
    <div className="w-full h-[7vh] flex justify-between border-b border-gray-200 shadow-md items-center relative z-50 bg-white">
      <div className="px-6 pb-1">
        <img className="h-14" src="../../assets/payzip.png" alt="" />
      </div>
      <div className="flex gap-4 px-10 text-center">
        <div className="flex items-center font-rubik text-lg">
          {user && "Hello"}
        </div>
        {user ? (
          <button
            ref={buttonContainerRef}
            onClick={() => setShowLogout((prev) => !prev)}
            className="flex items-center justify-center w-12 h-12 rounded-full bg-gray-200 text-xl font-medium text-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-gray-400 pt-1"
          >
            {user.firstName.split("")[0]}
          </button>
        ) : (
          <button
            onClick={() => {
              setLoading(true);
              setTimeout(() => {
                navigate("/signin");
              }, 2000);
            }}
            className="bg-black px-4 py-2 rounded-lg hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 hover:scale-105 shadow-md text-indigo-100 duration-150 font-raleway text-lg"
          >
            {loading ? (
              <img
                className="w-full h-6 animate-spin ease-linear"
                src="../assets/loading.svg"
                alt="Loading icon"
              ></img>
            ) : (
              "Signin"
            )}
          </button>
        )}
      </div>
      {showLogout && user && (
        <div
          ref={logoutBtnContainer}
          className="absolute right-3 top-[63px] bg-gray-200 h-[11rem] w-[13%] rounded-md shadow-lg text-wrap flex flex-col justify-between gap-3"
        >
          <div className="p-2 font-merriweather">
            <p className="text-gray-700 text-lg">
              {user.firstName} {user.lastName}
            </p>
            <p className="text-[0.8rem] text-gray-700 mb-2">{user.username}</p>
            <Link
              to={"/dashboard/edit"}
              className="text-sm underline text-blue-600"
            >
              Update Profile
            </Link>
          </div>

          <div className="flex items-center justify-center mb-1">
            <button
              onClick={() => {
                setLoading(true);
                setTimeout(() => {
                  navigate("/signin");
                }, 2000);
              }}
              className="bg-black px-4 py-2 rounded-lg hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 hover:scale-105 shadow-md text-indigo-100 duration-150 font-raleway text-lg"
            >
              {loading ? (
                <img
                  className="w-full h-6 animate-spin ease-linear"
                  src="../assets/loading.svg"
                  alt="Loading icon"
                ></img>
              ) : (
                "Logout"
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Topnav;
