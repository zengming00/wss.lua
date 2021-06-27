include $(TOPDIR)/rules.mk

PKG_NAME:=wss
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=apps
	CATEGORY:=Mypackages
	TITLE:=wss
	MAINTAINER:=zengming00@gmail.com
	DEPENDS:=+liblua
endef

define Package/$(PKG_NAME)/description
wss
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/getchinaip.sh $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wss.lua $(1)/usr/bin

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wss $(1)/etc/init.d

	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/chinaIP.txt $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/config.lua $(1)/etc

	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wss_clib.so $(1)/usr/lib/lua
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
