import React from "react";

const SendMoney = () => {
  return (
    <div className="bg-[rgba(0,0,0,.8)] absolute z-[100] top-0 left-0 w-screen h-screen flex flex-col items-center justify-center">
      <div className="bg-white w-[29rem] h-[24rem] flex flex-col gap-[3.2rem] rounded-lg">
        <div className="flex items-center justify-center h-[7rem] text-4xl font-bold pt-2 font-quicksand">
          <h1>Send Money</h1>
        </div>

        <div className="px-10 py-1">
          <div className="flex gap-3 items-center mb-1">
            <span className="flex items-center justify-center w-11 h-11 rounded-full bg-green-600 text-xl font-medium text-white focus:outline-none focus:ring-2 focus:ring-offset-1 focus:ring-gray-400 font-quicksand">
              A
            </span>
            <h1 className="text-xl font-bold  font-quicksand">Friend's Name</h1>
          </div>
          <div className="flex flex-col gap-1">
            <h3 className="">Amount (in Rs)</h3>
            <input
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-black mb-2"
              type="text"
              placeholder="Enter Amount"
            />
            <button className="bg-green-600 text-lg py-2 rounded-md text-white font-bold font-quicksand mt-1">
              Initiate Transfer
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SendMoney;
