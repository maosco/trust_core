################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../common_utils.c \
../decryption.c \
../digesting.c \
../dual_function_crypto.c \
../encryption.c \
../gen_purpose.c \
../key_management.c \
../objects.c \
../parallel.c \
../random.c \
../sessions.c \
../signing_macing.c \
../slots_tokens.c \
../tc_api.c \
../verify_sig_mac.c 

OBJS += \
./common_utils.o \
./decryption.o \
./digesting.o \
./dual_function_crypto.o \
./encryption.o \
./gen_purpose.o \
./key_management.o \
./objects.o \
./parallel.o \
./random.o \
./sessions.o \
./signing_macing.o \
./slots_tokens.o \
./tc_api.o \
./verify_sig_mac.o 

C_DEPS += \
./common_utils.d \
./decryption.d \
./digesting.d \
./dual_function_crypto.d \
./encryption.d \
./gen_purpose.d \
./key_management.d \
./objects.d \
./parallel.d \
./random.d \
./sessions.d \
./signing_macing.d \
./slots_tokens.d \
./tc_api.d \
./verify_sig_mac.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	g++ -O0 -g -Wall -c -fmessage-length=0 -fpermissive -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


