#!/bin/bash
# Regenerate weet_wiz icons from turtle.png (yellow/gold version)
# Run from anywhere — uses absolute paths

INPUT="/Users/jurajbadal/weet_wiz/src/images/turtle.png"
OUTDIR="/Users/jurajbadal/weet_wiz/src/icons"

for size in 16 32 48 128; do
    if [ "$size" = "16" ]; then
        resize_param="14x14"
    else
        resize_param="${size}x${size}"
    fi
    text_size=$(($size/6))
    magick \( "$INPUT" -resize $resize_param -background none -alpha set \) \
        \( -size ${size}x${size} -background none -fill "#333333" -gravity north -pointsize $text_size label:"WEET" \) -gravity north -composite \
        \( -size ${size}x${size} -background none -fill "#333333" -gravity south -pointsize $text_size label:"WIZ" \) -gravity south -composite \
        -size ${size}x${size} -gravity center -background none -extent ${size}x${size} \
        "${OUTDIR}/icon${size}.png"
done

echo "Icons generated successfully!"
