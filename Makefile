define CARGO_VENDOR_CONFIG_TOML
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
endef

export CARGO_VENDOR_CONFIG_TOML

all:
	echo "Choose vendor, config, remove-config"

vendor:
	cargo vendor --versioned-dirs

config:
	mkdir .cargo
	touch .cargo/config.toml
	echo "$$CARGO_VENDOR_CONFIG_TOML" >> .cargo/config.toml

remove-config:
	echo "# Comment out the following lines in .cargo/config.toml"
	echo "$$CARGO_VENDOR_CONFIG_TOML"

.PHONY: all

.SILENT: all vendor config remove-config
