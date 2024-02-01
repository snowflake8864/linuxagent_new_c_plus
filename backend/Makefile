###########################################################
.PHONY:all
all: $(TARGET)
	$(MAKE) -C osec_backend 


.PHONY:clean distclean
clean:
	rm -f $(TARGET_OBJS)
	#rm -f MagicArmor_0
	$(MAKE) -C osec_backend clean

distclean:
	rm -f $(TARGET_OBJS)
	rm -f $(TARGET)
	$(MAKE) -C osec_backend distclean

###########################################################
