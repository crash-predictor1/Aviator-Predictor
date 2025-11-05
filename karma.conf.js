/* globals module */
module.exports = function (config) {
  const shaVariant = config.fileVariant || "sha"; // keep same unless renamed

  config.set({
    frameworks: ["mocha", "chai"],
    files: ["dist/" + shaVariant + ".js", "test/hash_data.js", "test/dist/test_umd.js"],
    reporters: ["progress"],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    browsers: ["ChromeHeadless", "FirefoxHeadless"],
    autoWatch: false,
    singleRun: true,
    concurrency: Infinity,
    client: {
      mocha: {
        timeout: 10000,
      },
    },
  });
};
