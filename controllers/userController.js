const asyncHandler = require("express-async-handler")

const registerUser = asyncHandler(
    async (req, res) => {
        res.json({message: "Register the user"})
    })

const loginUser = asyncHandler(
    async (req, res) => {
        res.json({message: "login user"})
    })

const currentUser = asyncHandler(
    async (req, res) => {
        res.json({message: "Current user information"})
    })

module.exports = { registerUser, loginUser, currentUser }