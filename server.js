import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import startRouter from "./routes/startScenario.js";
import shortRouter from "./routes/shorten.js";
import uploadRouter from "./routes/upload.js";
import modulesRouter from "./routes/modules.js";
import health from "./routes/health.js";

dotenv.config();
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({limit:'2mb'}));
app.use(express.urlencoded({extended:true}));

app.use((req,res,next)=>{
  res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self' https://telegram.org; connect-src 'self' https://api.github.com " + (process.env.BASE_URL || "") + "; img-src 'self' data: https://i.ibb.co; style-src 'self' 'unsafe-inline';");
  next();
});

const limiter = rateLimit({windowMs:60000, max:100});
app.use(limiter);

app.use("/api/start-scenario", startRouter);
app.use("/api/shorten", shortRouter);
app.use("/api/upload", uploadRouter);
app.use("/api/modules", modulesRouter);
app.use("/health", health);

app.get("/", (_,res)=>res.send("CyberSmart Backend Active"));
const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=>console.log(`✅ Backend listening on ${PORT}`));
