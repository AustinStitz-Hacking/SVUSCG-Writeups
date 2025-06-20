# Our output file
output = open("oled-output.txt", "wt+")
# Open the byte string file
with open("image-hex.txt") as file:
    # Get first line of file
    content = str(file.read()).split("\n")[0]
    # Get individual hexadecimal bytes
    b = content.split(" ")

    # Add null bytes for padding to prevent index out of range errors
    for i in range(100): b.append("00")

    # Loop through 160 y values
    for y in reversed(range(160)):
        # Stores this row
        temp = ""
        # Loop through 160 x values
        for x in range(160):
            # Get index from x and y
            idx = y + (x // 8) * 0x80
            # Get value from index
            value = int(b[idx], 16) & (1 << (x & 7))
            # Print an O for on and space for off
            if value > 0:
                temp += "O"
            else:
                temp += " "
        # Write the line to our file
        output.write(temp + "\n")
# Close the file
output.close()
