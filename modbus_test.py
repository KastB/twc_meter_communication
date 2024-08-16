import struct

def calculate_crc(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

def interpret_data(data):
    result = []    
    # Interpret as 32-bit floats
    if len(data) >= 4:
        floats = [struct.unpack('>f', data[i:i+4])[0] for i in range(0, len(data) - 3, 4)]
        result.append(f"32-bit Floats: {floats}")
    
    # Interpret as string
    try:
        string_value = data.decode('ascii').rstrip('\x00')
        if string_value.isprintable():
            result.append(f"ASCII String: {string_value}")
    except UnicodeDecodeError:
        pass
    
    return '\n'.join(result)

def parse_modbus_rtu_message(byte_data, is_response=False):
    if len(byte_data) < 8:
        return "Invalid message: too short", len(byte_data)

    address = byte_data[0]
    function_code = byte_data[1]
    
    if not is_response:
        # Request message
        if function_code in [0x01, 0x02, 0x03, 0x04]:  # Read functions
            data_length = 6
        elif function_code in [0x05, 0x06]:  # Single write functions
            data_length = 6
        elif function_code in [0x0F, 0x10]:  # Multiple write functions
            data_length = 7 + byte_data[6]
        else:
            data_length = len(byte_data) - 2  # Unknown function, assume all remaining data
    else:
        # Response message
        if function_code in [0x01, 0x02, 0x03, 0x04]:  # Read functions response
            data_length = 3 + byte_data[2]
        elif function_code in [0x05, 0x06, 0x0F, 0x10]:  # Write functions response
            data_length = 6
        else:
            data_length = len(byte_data) - 2  # Unknown function, assume all remaining data

    message_length = data_length + 2  # Add 2 for CRC
    if len(byte_data) < message_length:
        return "Invalid message: incomplete", len(byte_data)

    data = byte_data[2:data_length]
    crc_received = struct.unpack('<H', byte_data[data_length:message_length])[0]
    crc_calculated = calculate_crc(byte_data[:data_length])

    message_type = "Response" if is_response else "Request"
    
    result = f"{message_type}:\n"
    result += f"Raw Hex: {byte_data[:message_length].hex()}\n"
    result += f"Address: {address}\n"
    result += f"Function Code: {function_code:02X}\n"
    
    if is_response and function_code == 0x03:
        result += f"Number of bytes: {data[0]}\n"
        register_data = data[1:]
        result += f"Register Data: {register_data.hex()}\n"
        result += "Interpreted Data:\n"
        result += interpret_data(register_data)
    else:
        result += f"Data: {data.hex()}\n"
    
    result += f"\nCRC (received): {crc_received:04X}\n"
    result += f"CRC (calculated): {crc_calculated:04X}\n"
    result += f"CRC Match: {crc_received == crc_calculated}\n"

    return result, message_length


def format_hex(byte_data):
    hex_string = ''.join(f'{byte:02X}' for byte in byte_data)
    formatted_hex = ''.join(hex_string[i:i+48]
                              for i in range(0, len(hex_string), 48))
    return formatted_hex


def parse_modbus_rtu(byte_data):

    request_result, request_length = parse_modbus_rtu_message(byte_data)
    byte_data = byte_data[request_length:]
    response_result, request_length = parse_modbus_rtu_message(byte_data, is_response=True)
    byte_data = byte_data[request_length:]
    print(f"request_length {request_length}")
    print(f"remaining_data {format_hex(byte_data)}")
    
    return f"{request_result}\n{response_result}", byte_data

def main():
    with open('data.txt', 'r') as file:
        for line_number, line in enumerate(file, 1):
            # Convert binary string to bytes

            binary_string = line.strip()
            byte_data = bytes(int(binary_string[i:i+8], 2)
                              for i in range(0, len(binary_string), 8))
            byte_data_len = -1
            counter = 1
            while byte_data and byte_data_len != len(byte_data):
                byte_data_len = len(byte_data)
                print(f"Line {line_number}#{counter}:")
                parsed_string, remaining_data = parse_modbus_rtu(byte_data)
                print(parsed_string)
                print('-' * 40)
                byte_data = remaining_data
                counter += 1

if __name__ == "__main__":
    main()