SST_PATH = sst/src
SST_TEST_PATH = sst/test
SRC_PATH = src
TEST_PATH = test
DEPLOY_PATH = deploy

all:
	@echo "Building sst..."
	@make -C $(SST_PATH)
#	@echo "Building sst test..."
#	@make -C $(SST_TEST_PATH)
	@echo "Building deploy..."
	@make -C $(DEPLOY_PATH)
	@echo "Building keychain sdk and keychain service..."
	@make -C $(SRC_PATH)
#	@echo "Building keychain test..."
#	@make -C $(TEST_PATH)

clean:
	@make clean -C $(SST_PATH)
	@make clean -C $(SST_TEST_PATH)
	@make clean -C $(DEPLOY_PATH)
	@make clean -C $(SRC_PATH)
#	@make clean -C $(TEST_PATH)

