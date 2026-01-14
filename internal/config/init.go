package config

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

func InitConfig() {
	if configFile := os.Getenv("DESKTOP_SECRETS_CONFIG_FILE"); configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		if exePath, err := os.Executable(); err == nil {
			viper.AddConfigPath(filepath.Dir(exePath))
		}
	}

	viper.SetDefault("ttl", 15)

	var configFileNotFoundError viper.ConfigFileNotFoundError
	if err := viper.ReadInConfig(); err != nil {
		if errors.As(err, &configFileNotFoundError) {
			if err = viper.WriteConfigAs("config.yaml"); err != nil {
				log.Printf("failed to write default config: %v", err)
			}
		}
	}

}
