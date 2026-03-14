package config

import (
	"desktopsecrets/internal/static"
	"desktopsecrets/internal/utils"
	"errors"
	"os"
	"path"

	"github.com/spf13/viper"
)

func InitConfig() error {
	var configFile string

	if configFile = os.Getenv("DESKTOP_SECRETS_CONFIG_FILE"); configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		if settingsDir, err := utils.GetSettingsDirectory(); err == nil {
			configFile = path.Join(settingsDir, "config.yaml")
			viper.SetConfigFile(configFile)
		} else {
			return err
		}
	}

	viper.SetDefault("ttl", static.DefaultTTL)

	var configFileNotFoundError viper.ConfigFileNotFoundError
	if err := viper.ReadInConfig(); err != nil {
		if errors.As(err, &configFileNotFoundError) {
			if err = viper.WriteConfigAs(configFile); err != nil {
				return err
			}
		}
	}

	return nil
}
