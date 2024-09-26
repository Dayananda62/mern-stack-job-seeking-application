import express from 'express'
import dotenv from "dotenv"
import cors from 'cors'
import cookieParser from "cookie-parser"
import fileUpload from 'express-fileupload'
import userRouter from "./routers/userRouter.js"
import applicationRouter from "./routers/applicationRouter.js"
import jobRouter from "./routers/jobRouter.js"
import { dbConnection } from './database/dbConnection.js'
import { errorMiddleWare } from './middlewares/error.js'

const app=express()
dotenv.config({path:"./config/config.env"});

app.use(cors({
    origin:[process.env.FRONTEND_URL],
    methods:['GET','POST','DELETE','PUT'],
    credentials:true
}))

app.use(cookieParser())
app.use(express.json());
app.use(express.urlencoded({extended:true}))

app.use(fileUpload({
    useTempFiles:true,
    tempFileDir:"/tmp/"
}))

app.use('/api/v1/user',userRouter)
app.use('/api/v1/application',applicationRouter)
app.use('/api/v1/job',jobRouter)

app.use(errorMiddleWare)

dbConnection()
export default app;