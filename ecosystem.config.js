module.exports = {
  apps: [
    {
      name: "retelio-backend",
      script: "dist/index.js",
      instances: 1,
      exec_mode: "cluster",
      watch: false,
      env: {
        NODE_ENV: "production",
        PORT: process.env.PORT || 3001,
        BASE_PATH: "/reteilo/backend",
        PUBLIC_BASE_URL: "https://client.iqonic.design/reteilo/backend",
      },
      error_file: "./logs/pm2-error.log",
      out_file: "./logs/pm2-out.log",
      time: true,
      max_memory_restart: "512M",
    },
  ],
};


