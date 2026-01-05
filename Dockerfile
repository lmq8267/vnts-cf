FROM node:18-bookworm   
WORKDIR /app  
  
# 安装系统依赖  
RUN apt-get update && apt-get install -y \  
    protobuf-compiler \  
    && rm -rf /var/lib/apt/lists/*  
  
# 复制项目文件  
COPY package*.json ./  
RUN npm install  
  
COPY . .  
  
  
EXPOSE 29872  
  
CMD ["npm", "run", "dev"]
