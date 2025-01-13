const fs = require('fs')
const path = require("path")

module.exports.getResourceServerConfig = (resourceServerId) => {
  const configPath = process.env.CONFIG_PATH ? process.env.CONFIG_PATH : process.env.LAMBDA_TASK_ROOT

  let configData = JSON.parse(fs.readFileSync(path.resolve(configPath, "resource_servers.json")))
  let foundConfig = configData.filter(config => config.id === resourceServerId)
  if(foundConfig.length > 0) {
    return foundConfig[0]
  }
  else {
    return {}
  }
}
