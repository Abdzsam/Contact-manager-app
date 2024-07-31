const asyncHandler = require("express-async-handler")
const argon2 = require("argon2");
const User = require("../models/userModel");


const registerUser = asyncHandler(
    async (req, res) => {
        const {username, email, password} = req.body;
        if(!username || !email || !password){
            res.status(400)
            throw new Error("All fields are mandatory!")
        }
        const userAvailable = await User.findOne({email})
        if(userAvailable){
            res.status(400)
            throw new Error("User already registered!")
        }

        const hashPassword = await argon2.hash(password, {
            type: argon2.argon2id,        
            memoryCost: 2 ** 16,         
            timeCost: 3,                  
            parallelism: 1
        })

        console.log("Hashed Password: ", hashPassword)

        const user = await User.create({
            username,
            email,
            password: hashPassword,
        })
        res.json(`User created ${user}`)

        if(user) {
            res.status(201).json({_id: user.id, email: user.email})
        }
        else{
            res.status(400)
            throw new Error("User data is not valid")
        }
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