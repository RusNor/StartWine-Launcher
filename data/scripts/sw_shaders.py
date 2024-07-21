from enum import Enum

class Shaders(Enum):

    src_psw_blue = """
    /////////////////// Plasma waves

    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */

    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.25, 0.5, 1.0, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;
    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.2, 0.7, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            line = line + circle;
            lines += line * lineColor * rand;
        }
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_red = """
    /////////////////// Plasma waves

    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */

    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.5, 0.25, 0.25, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.25, 0.2, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_teal = """
    /////////////////// Plasma waves
    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */
    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.25, 0.5, 0.5, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.25, 0.2, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_mint = """
    /////////////////// Plasma waves
    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */
    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.35, 0.5, 0.2, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.25, 0.2, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_yellow = """
    /////////////////// Plasma waves
    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */
    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.5, 0.5, 0.25, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.25, 0.2, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_purple = """
    /////////////////// Plasma waves
    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */
    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.35, 0.25, 0.5, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.2, 0.25, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_brown = """
    /////////////////// Plasma waves
    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */
    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.5, 0.35, 0.25, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.25, 0.2, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_psw_grey = """
    /////////////////// Plasma waves
    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */
    const float overallSpeed = 0.2;
    const float gridSmoothWidth = 0.015;
    const float axisWidth = 0.05;
    const float majorLineWidth = 0.025;
    const float minorLineWidth = 0.0125;
    const float majorLineFrequency = 5.0;
    const float minorLineFrequency = 1.0;
    const vec4 gridColor = vec4(0.5);
    const float scale = 5.0;
    const vec4 lineColor = vec4(0.4, 0.4, 0.5, 1.0);
    const float minLineWidth = 0.02;
    const float maxLineWidth = 0.5;
    const float lineSpeed = 1.0 * overallSpeed;
    const float lineAmplitude = 1.0;
    const float lineFrequency = 0.2;
    const float warpSpeed = 0.2 * overallSpeed;
    const float warpFrequency = 0.5;
    const float warpAmplitude = 1.0;
    const float offsetFrequency = 0.5;
    const float offsetSpeed = 1.33 * overallSpeed;
    const float minOffsetSpread = 0.6;
    const float maxOffsetSpread = 2.0;
    const int linesPerGroup = 16;

    const vec4[] bgColors = vec4[]
        (
            lineColor * 0.5,
            lineColor - vec4(0.2, 0.2, 0.2, 1)
            );

    #define drawCircle(pos, radius, coord) smoothstep(radius + gridSmoothWidth, radius, length(coord - (pos)))

    #define drawSmoothLine(pos, halfWidth, t) smoothstep(halfWidth, 0.0, abs(pos - (t)))

    #define drawCrispLine(pos, halfWidth, t) smoothstep(halfWidth + gridSmoothWidth, halfWidth, abs(pos - (t)))

    #define drawPeriodicLine(freq, width, t) drawCrispLine(freq / 2.0, width, abs(mod(t, freq) - (freq) / 2.0))

    float drawGridLines(float axis)   
    {
        return   drawCrispLine(0.0, axisWidth, axis)
               + drawPeriodicLine(majorLineFrequency, majorLineWidth, axis)
               + drawPeriodicLine(minorLineFrequency, minorLineWidth, axis);
    }

    float drawGrid(vec2 space)
    {
        return min(1., drawGridLines(space.x)
                      +drawGridLines(space.y));
    }

    // probably can optimize w/ noise, but currently using fourier transform
    float random(float t)
    {
        return (cos(t) + cos(t * 1.3 + 1.3) + cos(t * 1.4 + 1.4)) / 3.0;   
    }

    float getPlasmaY(float x, float horizontalFade, float offset)   
    {
        return random(x * lineFrequency + iTime * lineSpeed) * horizontalFade * lineAmplitude + offset;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 space = (fragCoord - iResolution.xy / 2.0) / iResolution.x * 2.0 * scale;
        
        float horizontalFade = 1.0 - (cos(uv.x * 6.28) * 0.5 + 0.5);
        float verticalFade = 1.0 - (cos(uv.y * 6.28) * 0.5 + 0.5);

        // fun with nonlinear transformations! (wind / turbulence)
        space.y += random(space.x * warpFrequency + iTime * warpSpeed) * warpAmplitude * (0.5 + horizontalFade);
        space.x += random(space.y * warpFrequency + iTime * warpSpeed + 2.0) * warpAmplitude * horizontalFade;
        
        vec4 lines = vec4(0);
        
        for(int l = 0; l < linesPerGroup; l++)
        {
            float normalizedLineIndex = float(l) / float(linesPerGroup);
            float offsetTime = iTime * offsetSpeed;
            float offsetPosition = float(l) + space.x * offsetFrequency;
            float rand = random(offsetPosition + offsetTime) * 0.5 + 0.5;
            float halfWidth = mix(minLineWidth, maxLineWidth, rand * horizontalFade) / 2.0;
            float offset = random(offsetPosition + offsetTime * (1.0 + normalizedLineIndex)) * mix(minOffsetSpread, maxOffsetSpread, horizontalFade);
            float linePosition = getPlasmaY(space.x, horizontalFade, offset);
            float line = drawSmoothLine(linePosition, halfWidth, space.y) / 2.0 + drawCrispLine(linePosition, halfWidth * 0.15, space.y);
            
            float circleX = mod(float(l) + iTime * lineSpeed, 25.0) - 12.0;
            vec2 circlePosition = vec2(circleX, getPlasmaY(circleX, horizontalFade, offset));
            float circle = drawCircle(circlePosition, 0.01, space) * 4.0;
            
            
            line = line + circle;
            lines += line * lineColor * rand;
        }
        
        fragColor = mix(bgColors[0], bgColors[1], uv.x);
        fragColor *= verticalFade;
        fragColor.a = 1.0;
        // debug grid:
        //fragColor = mix(fragColor, gridColor, drawGrid(space));
        fragColor += lines;
    }
    """

    src_dr_teal = """
    /////////////////// Windows Terminal Damask Rose
    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.30, 0.35, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.57, 0.6 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.55, 0.9, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_red = """
    /////////////////// Windows Terminal Damask Rose
    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.9, 0.6, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.95, 0.7 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.99, 0.9, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_blue = """
    /////////////////// Damask Rose
    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.6, 0.5, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.6, 0.7 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.6, 0.9, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_purple = """
    /////////////////// Windows Terminal Damask Rose
    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.7, 0.5, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.7, 0.6 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.7, 0.7, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_yellow = """
    /////////////////// Windows Terminal Damask Rose
    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.1, 0.9, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.1, 0.9 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.1, 0.9, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_mint = """
    /////////////////// Windows Terminal Damask Rose
    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.23, 0.7, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.23, 0.8 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.23, 0.9, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_brown = """
    /////////////////// Windows Terminal Damask Rose

    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.05, 0.7, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.05, 0.8 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.05, 0.9, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_dr_grey = """
    /////////////////// Windows Terminal Damask Rose

    // CC0: Windows Terminal Damask Rose
    //  Been tinkering creating Windows Terminal shaders
    //  Created this as a version of an earlier shader
    //  Thought it turned out decent so sharing
    // https://mrange.github.io/windows-terminal-shader-gallery/
    // Define to use a faster atan implementation
    //  Introduces slight assymmetries that don't look outright terrible at least
    //#define FASTATAN

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))


    #if defined(FASTATAN)
    #define ATAN atan_approx
    #else
    #define ATAN atan
    #endif

    const float hf = 0.015;

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    float height(vec2 p) {
    //  float tm = TIME-2.*length(p);
      float tm = TIME;
      const float xm = 0.5*0.005123;
      float ym = mix(0.125, 0.25, 0.5-0.5*cos(TAU*TIME/600.0));

      p *= 0.4;
      
      float d = length(p);
      float c = 1E6;
      float x = pow(d, 0.1);
      float y = (ATAN(p.x, p.y)+0.05*tm-2.0*d) / TAU;
      
      for (float i = 0.; i < 3.; ++i) {
        float v = length(fract(vec2(x - tm*i*xm, fract(y + i*ym)*.5)*20.)*2.-1.);
        c = pmin(c, v, 0.125);
      }

      float h =  (-hf+hf*(pabs(tanh_approx(5.5*d-80.*c*c*d*d*(.55-d))-0.25*d, 0.25)));
      return h;
    }

    vec3 normal(vec2 p) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = -2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 color(vec2 p) {
      const float ss = 1.25;
      const float hh = 1.95; 

      const vec3 lp1 = -vec3(1.0 , hh, -1.0)*vec3(ss, 1.0, ss);
      const vec3 lp2 = -vec3(-1.0, hh, -1.0)*vec3(ss, 1.0, ss);

      const vec3 lcol1 = HSV2RGB(vec3(0.6, 0.1, 2.0));
      const vec3 lcol2 = HSV2RGB(vec3(0.6, 0.2 , 2.0));
      const vec3 mat   = HSV2RGB(vec3(0.6, 0.3, 0.05));
      const float spe  = 16.0;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, 8.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, 0.0, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      float dm = tanh_approx(abs(h)*120.0);
      float rm = dm;
      dm *= dm;

      vec3 lpow1 = dm*mat*lcol1;
      vec3 lpow2 = dm*mat*lcol2;

      vec3 col = vec3(0.0);
      col += diff1*diff1*lpow1;
      col += diff2*diff2*lpow2;

      col += rm*pow(ref1, spe)*lcol1;
      col += rm*pow(ref2, spe)*lcol2;

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = color(p);

      col = aces_approx(col);
      col = sRGB(col);
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_pwb_blue = """
    ////////////////// Blue parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.7;
       col.g = uv.y - 0.5;
       col.b = uv.y - 0.3;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_red = """
    ////////////////// Red parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.35;
       col.g = uv.y - 0.7;
       col.b = uv.y - 0.7;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_teal = """
    ////////////////// Teal parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.7;
       col.g = uv.y - 0.3;
       col.b = uv.y - 0.3;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_mint = """
    ////////////////// Mint parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.5;
       col.g = uv.y - 0.3;
       col.b = uv.y - 0.7;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_golden = """
    ////////////////// Golden parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.3;
       col.g = uv.y - 0.3;
       col.b = uv.y - 0.7;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_purple = """
    ////////////////// Purple parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.5;
       col.g = uv.y - 0.7;
       col.b = uv.y - 0.3;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_brown = """
    ////////////////// Brown parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.3;
       col.g = uv.y - 0.5;
       col.b = uv.y - 0.7;

        fragColor = vec4(col,1.0);
    }
    """

    src_pwb_gray = """
    ////////////////// Gray parabolic waves background

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        vec2 uv =  (-0.8 * fragCoord + iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 8.0; i++){
        uv.y += i * 0.1 / i * 
          sin(uv.y * i * i + iTime * 0.3) * sin(uv.x * i * i + iTime * 0.3);
      }

       vec3 col;
       col.r  = uv.y - 0.5;
       col.g = uv.y - 0.5;
       col.b = uv.y - 0.5;

        fragColor = vec4(col,1.0);
    }
    """


    src_mac = """
    /////////////////// MacOS Monterey 2

    vec3 sin_shape(in vec2 uv, in float offset_y) {
      // Time varying pixel color
      float y = sin((uv.x + iTime * -0.06 + offset_y) * 5.5);

      float x = uv.x * 8.;
      float a=1.;
        for (int i=0; i<5; i++) {
            x*=0.53562;
            x+=6.56248;
            y+=sin(x)*a;
            a*=.5;
        }

      float y0 = step(0.0, y * 0.08 - uv.y + offset_y);
      return vec3(y0, y0, y0);
    }

    vec2 rotate(vec2 coord, float alpha) {
      float cosA = cos(alpha);
      float sinA = sin(alpha);
      return vec2(coord.x * cosA - coord.y * sinA, coord.x * sinA + coord.y * cosA);
    }

    vec3 scene(in vec2 uv) {
        vec3 col = vec3(0.0, 0.0, 0.0);
        col += sin_shape(uv, 0.3) * 0.2;
        col += sin_shape(uv, 0.7) * 0.2;
        col += sin_shape(uv, 1.1) * 0.2;

        vec3 fragColor;

    if (col.x >= 0.6 ) {fragColor = vec3(0.12549019607843137, 0.043137254901960784, 0.4117647058823529);
        } else if (col.x >= 0.4) {fragColor = vec3(0.27254901960784315, 0.05411764705882353, 0.607843137254902);
        } else if (col.x >= 0.2) {fragColor = vec3(0.7215686274509804, 0.19215686274509805, 0.7294117647058823);
        } else {fragColor = vec3(0.8352941176470589, 0.3764705882352941, 0.6588235294117647);
        }
        return fragColor;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        fragCoord = rotate(fragCoord + vec2(0.0, -300.0), 0.5);
        // Normalized pixel coordinates (from 0 to 1)
        vec3 col0 = scene((fragCoord * 2.0)/iResolution.xy);
        vec3 col1 = scene((-(fragCoord * 2.0) + vec2(1.0, 0.0))/iResolution.xy);
        vec3 col2 = scene((-(fragCoord * 2.0) + vec2(1.0, 1.0))/iResolution.xy);
        vec3 col3 = scene(((fragCoord * 2.0) + vec2(0.0, 1.0))/iResolution.xy);

        // Output to screen
        fragColor = vec4((col0 + col1 + col2 + col3) / 4.0,1.0);
    }
    """

    src_nr = """
    #define PI          3.141592654
    #define TAU         (2.0*PI)

    #define TIME        iTime
    #define RESOLUTION  iResolution

    vec3 hsv2rgb(vec3 c) {
      const vec4 K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
      vec3 p = abs(fract(c.xxx + K.xyz) * 6.0 - K.www);
      return c.z * mix(K.xxx, clamp(p - K.xxx, 0.0, 1.0), c.y);
    }

    float hash(in float co) {
      return fract(sin(co*12.9898) * 13758.5453);
    }

    float hash(in vec2 co) {
      return fract(sin(dot(co.xy ,vec2(12.9898,58.233))) * 13758.5453);
    }

    float psin(float a) {
      return 0.5 + 0.5*sin(a);
    }

    float mod1(inout float p, float size) {
      float halfsize = size*0.5;
      float c = floor((p + halfsize)/size);
      p = mod(p + halfsize, size) - halfsize;
      return c;
    }

    float circle(vec2 p, float r) {
      return length(p) - r;
    }

    float box(vec2 p, vec2 b) {
      vec2 d = abs(p)-b;
      return length(max(d,0.0)) + min(max(d.x,d.y),0.0);
    }

    float planex(vec2 p, float w) {
      return abs(p.y) - w;
    }

    float planey(vec2 p, float w) {
      return abs(p.x) - w;
    }

    float pmin(float a, float b, float k) {
      float h = clamp( 0.5+0.5*(b-a)/k, 0.0, 1.0 );
      return mix( b, a, h ) - k*h*(1.0-h);
    }

    float pmax(float a, float b, float k) {
      return -pmin(-a, -b, k);
    }

    float sun(vec2 p) {
      const float ch = 0.0125;
      vec2 sp = p;
      vec2 cp = p;
      mod1(cp.y, ch*6.0);

      float d0 = circle(sp, 0.5);
      float d1 = planex(cp, ch);
      float d2 = p.y+ch*3.0;

      float d = d0;
      d = pmax(d, -max(d1, d2), ch*2.0);

      return d;
    }

    float city(vec2 p) {
      float sd = circle(p, 0.5);
      float cd = 1E6;

      const float count = 5.0;
      const float width = 0.1;

      for (float i = 0.0; i < count; ++i) {
        vec2 pp = p;
        pp.x += i*width/count;
        float nn = mod1(pp.x, width);
        float rr = hash(nn+sqrt(3.0)*i);
        float dd = box(pp-vec2(0.0, -0.5), vec2(0.02, 0.35*(1.0-smoothstep(0.0, 5.0, abs(nn)))*rr+0.1));
        cd = min(cd, dd);
      }

      return max(sd,cd);
    }
    vec3 sunEffect(vec2 p) {
      float aa = 4.0 / RESOLUTION.y;

      vec3 col = vec3(0.1);
      vec3 skyCol1 = hsv2rgb(vec3(283.0/360.0, 0.83, 0.16));
      vec3 skyCol2 = hsv2rgb(vec3(297.0/360.0, 0.79, 0.43));
      col = mix(skyCol1, skyCol2, pow(clamp(0.5*(1.0+p.y+0.1*sin(4.0*p.x+TIME*0.5)), 0.0, 1.0), 4.0));

      p.y -= 0.375;
      float ds = sun(p);
      float dc = city(p);

      float dd = circle(p, 0.5);

      vec3 sunCol = mix(vec3(1.0, 1.0, 0.0), vec3(1.0, 0.0, 1.0), clamp(0.5 - 1.0*p.y, 0.0, 1.0));
      vec3 glareCol = sqrt(sunCol);
      vec3 cityCol = sunCol*sunCol;

      col += glareCol*(exp(-30.0*ds))*step(0.0, ds);


      float t1 = smoothstep(0.0, 0.075, -dd);
      float t2 = smoothstep(0.0, 0.3, -dd);
      col = mix(col, sunCol, smoothstep(-aa, 0.0, -ds));
      col = mix(col, glareCol, smoothstep(-aa, 0.0, -dc)*t1);
      col += vec3(0.0, 0.25, 0.0)*(exp(-90.0*dc))*step(0.0, dc)*t2;

    //  col += 0.3*psin(d*400);

      return col;
    }

    float ground(vec2 p) {
      p.y += TIME*80.0;
      p *= 0.075;
      vec2 gp = p;
      gp = fract(gp) - vec2(0.5);
      float d0 = abs(gp.x);
      float d1 = abs(gp.y);
      float d2 = circle(gp, 0.05);

      const float rw = 2.5;
      const float sw = 0.0125;

      vec2 rp = p;
      mod1(rp.y, 12.0);
      float d3 = abs(rp.x) - rw;
      float d4 = abs(d3) - sw*2.0;
      float d5 = box(rp, vec2(sw*2.0, 2.0));
      vec2 sp = p;
      mod1(sp.y, 4.0);
      sp.x = abs(sp.x);
      sp -= vec2(rw - 0.125, 0.0);
      float d6 = box(sp, vec2(sw, 1.0));

      float d = d0;
      d = pmin(d, d1, 0.1);
      d = max(d, -d3);
      d = min(d, d4);
      d = min(d, d5);
      d = min(d, d6);

      return d;
    }

    vec3 groundEffect(vec2 p) {
      vec3 ro = vec3(0.0, 20.0, 0.0);
      vec3 ww = normalize(vec3(0.0, -0.025, 1.0));
      vec3 uu = normalize(cross(vec3(0.0,1.0,0.0), ww));
      vec3 vv = normalize(cross(ww,uu));
      vec3 rd = normalize(p.x*uu + p.y*vv + 2.5*ww);

      float distg = (-9.0 - ro.y)/rd.y;

      const vec3 shineCol = 0.75*vec3(0.5, 0.75, 1.0);
      const vec3 gridCol = vec3(1.0);

      vec3 col = vec3(0.0);
      if (distg > 0.0) {
        vec3 pg = ro + rd*distg;
        float aa = length(dFdx(pg))*0.0002*RESOLUTION.x;

        float dg = ground(pg.xz);

        col = mix(col, gridCol, smoothstep(-aa, 0.0, -(dg+0.0175)));
        col += shineCol*(exp(-10.0*clamp(dg, 0.0, 1.0)));
        col = clamp(col, 0.0, 1.0);

    //    col += 0.3*psin(dg*100);
        col *= pow(1.0-smoothstep(ro.y*3.0, 220.0+ro.y*2.0, distg), 2.0);
      }

      return col;
    }

    vec3 postProcess(vec3 col, vec2 q)  {
      col = clamp(col,0.0,1.0);
    //  col=pow(col,vec3(0.75));
      col=col*0.6+0.4*col*col*(3.0-2.0*col);
      col=mix(col, vec3(dot(col, vec3(0.33))), -0.4);
      col*=0.5+0.5*pow(19.0*q.x*q.y*(1.0-q.x)*(1.0-q.y),0.7);
      return col;
    }

    vec3 effect(vec2 p, vec2 q) {
      vec3 col = vec3(0.0);

      vec2 off = vec2(0.0, 0.0);

      col += sunEffect(p+off);
      col += groundEffect(p+off);

      col = postProcess(col, q);
      return col;
    }

    void mainImage(out vec4 fragColor, vec2 fragCoord) {
      vec2 q = fragCoord/iResolution.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x / RESOLUTION.y;

      vec3 col = effect(p, q);

      fragColor = vec4(col, 1.0);
    }
    """

    src_ap = """
    // Originally from: https://www.shadertoy.com/view/wsjBD3
    // License CC0: A battered alien planet
    //  Been experimenting with space inspired shaders

    #define PI  3.141592654
    #define TAU (2.0*PI)

    #define TOLERANCE       0.00001
    #define MAX_ITER        65
    #define MIN_DISTANCE    0.01
    #define MAX_DISTANCE    9.0

    const vec3  skyCol1       = vec3(0.35, 0.45, 0.6);
    const vec3  skyCol2       = vec3(0.4, 0.7, 1.0);
    const vec3  skyCol3       = pow(skyCol1, vec3(0.25));
    const vec3  sunCol1       = vec3(1.0,0.6,0.4);
    const vec3  sunCol2       = vec3(1.0,0.9,0.7);
    const vec3  smallSunCol1  = vec3(1.0,0.5,0.25)*0.5;
    const vec3  smallSunCol2  = vec3(1.0,0.5,0.25)*0.5;
    const vec3  mountainColor = 1.0*sqrt(vec3(0.95, 0.65, 0.45));
    const float cellWidth     = 1.0;
    const vec4  planet        = vec4(80.0, -20.0, 100.0, 50.0)*1000.0;

    void rot(inout vec2 p, float a) {
      float c = cos(a);
      float s = sin(a);
      p = vec2(p.x*c + p.y*s, -p.x*s + p.y*c);
    }

    vec2 mod2(inout vec2 p, vec2 size) {
      vec2 c = floor((p + size*0.5)/size);
      p = mod(p + size*0.5,size) - size*0.5;
      return c;
    }

    float circle(vec2 p, float r) {
      return length(p) - r;
    }

    float egg(vec2 p, float ra, float rb) {
      const float k = sqrt(3.0);
      p.x = abs(p.x);
      float r = ra - rb;
      return ((p.y<0.0)       ? length(vec2(p.x,  p.y    )) - r :
              (k*(p.x+r)<p.y) ? length(vec2(p.x,  p.y-k*r)) :
                                  length(vec2(p.x+r,p.y    )) - 2.0*r) - rb;
    }

    vec2 hash(vec2 p) {
      p = vec2(dot (p, vec2 (127.1, 311.7)), dot (p, vec2 (269.5, 183.3)));
      return -1. + 2.*fract (sin (p)*43758.5453123);
    }

    vec2 raySphere(vec3 ro, vec3 rd, vec4 sphere) {
      vec3 center = sphere.xyz;
      float radius = sphere.w;
      vec3 m = ro - center.xyz;
      float b = dot(m, rd);
      float c = dot(m, m) - radius*radius;
      if(c > 0.0 && b > 0.0) return vec2(-1.0, -1.0);
      float discr = b * b - c;
      if(discr < 0.0) return vec2(-1.0);
      float normalMultiplier = 1.0;
      float s = sqrt(discr);
      float t0 = -b - s;
      float t1 = -b + s;;
      return vec2(t0, t1);
    }

    float noize1(vec2 p) {
      vec2 n = mod2(p, vec2(cellWidth));
      vec2 hh = hash(sqrt(2.0)*(n+1000.0));
      hh.x *= hh.y;

      float r = 0.225*cellWidth;

      float d = circle(p, 2.0*r);

      float h = hh.x*smoothstep(0.0, r, -d);

      return h*0.25;
    }

    float noize2(vec2 p) {
      vec2 n = mod2(p, vec2(cellWidth));
      vec2 hh = hash(sqrt(2.0)*(n+1000.0));
      hh.x *= hh.y;

      rot(p, TAU*hh.y);
      float r = 0.45*cellWidth;

    //  float d = circle(p, 1.0*r);
      float d = egg(p, 0.75*r, 0.5*r*abs(hh.y));

      float h = (hh.x)*smoothstep(0.0, r, -2.0*d);

      return h*0.275;
    }

    float height(vec2 p, float dd, int mx) {
      const float aa   = 0.45;
      const float ff   = 2.03;
      const float tt   = 1.2;
      const float oo   = 3.93;
      const float near = 0.25;
      const float far  = 0.65;

      float a = 1.0;
      float o = 0.2;
      float s = 0.0;
      float d = 0.0;

      int i = 0;

      for (; i < 4;++i) {
        float nn = a*noize2(p);
        s += nn;
        d += abs(a);
        p += o;
        a *= aa;
        p *= ff;
        o *= oo;
        rot(p, tt);
      }

      float lod = s/d;

      float rdd = dd/MAX_DISTANCE;
      mx = int(mix(float(4), float(mx), step(rdd, far)));

      for (; i < mx; ++i) {
        float nn = a*noize1(p);
        s += nn;
        d += abs(a);
        p += o;
        a *= aa;
        p *= ff;
        o *= oo;
        rot(p, tt);
      }

      float hid = (s/d);

      return mix(hid, lod, smoothstep(near, far, rdd));
    }

    float loheight(vec2 p, float d) {
      return height(p, d, 0);
    }

    float height(vec2 p, float d) {
      return height(p, d, 6);
    }

    float hiheight(vec2 p, float d) {
      return height(p, d, 8);
    }

    vec3 normal(vec2 p, float d) {
      vec2 eps = vec2(0.00125, 0.0);

      vec3 n;

      n.x = (hiheight(p - eps.xy, d) - hiheight(p + eps.xy, d));
      n.y = 2.0*eps.x;
      n.z = (hiheight(p - eps.yx, d) - hiheight(p + eps.yx, d));

      return normalize(n);
    }

    const float stepLength[] = float[](0.9, 0.25);

    float march(vec3 ro, vec3 rd, out int max_iter) {
      float dt = 0.1;
      float d = MIN_DISTANCE;
      int currentStep = 0;
      float lastd = d;
      for (int i = 0; i < MAX_ITER; ++i)
      {
        vec3 p = ro + d*rd;
        float h = height(p.xz, d);

        if (d > MAX_DISTANCE) {
          max_iter = i;
          return MAX_DISTANCE;
        }

        float hd = p.y - h;

        if (hd < TOLERANCE) {
          ++currentStep;
          if (currentStep >= stepLength.length()) {
            max_iter = i;
            return d;
          }

          d = lastd;
          continue;
        }

        float sl = stepLength[currentStep];

        dt = max(hd, TOLERANCE)*sl + 0.0025*d;
        lastd = d;
        d += dt;
      }

      max_iter = MAX_ITER;
      return MAX_DISTANCE;
    }

    vec3 sunDirection() {
      return normalize(vec3(-0.5, 0.085, 1.0));
    }

    vec3 smallSunDirection() {
      return normalize(vec3(-0.2, -0.05, 1.0));
    }

    float psin(float f) {
      return 0.5 + 0.5*sin(f);
    }

    vec3 skyColor(vec3 ro, vec3 rd) {
      vec3 sunDir = sunDirection();
      vec3 smallSunDir = smallSunDirection();

      float sunDot = max(dot(rd, sunDir), 0.0);
      float smallSunDot = max(dot(rd, smallSunDir), 0.0);

      float angle = atan(rd.y, length(rd.xz))*2.0/PI;

      vec3 skyCol = mix(mix(skyCol1, skyCol2, max(0.0, angle)), skyCol3, clamp(-angle*2.0, 0.0, 1.0));

      vec3 sunCol = 0.5*sunCol1*pow(sunDot, 20.0) + 8.0*sunCol2*pow(sunDot, 2000.0);
      vec3 smallSunCol = 0.5*smallSunCol1*pow(smallSunDot, 200.0) + 8.0*smallSunCol2*pow(smallSunDot, 20000.0);

      vec3 dust = pow(sunCol2*mountainColor, vec3(1.75))*smoothstep(0.05, -0.1, rd.y)*0.5;

      vec2 si = raySphere(ro, rd, planet);

      vec3 planetSurface = ro + si.x*rd;
      vec3 planetNormal = normalize(planetSurface - planet.xyz);
      float planetDiff = max(dot(planetNormal, sunDir), 0.0);
      float planetBorder = max(dot(planetNormal, -rd), 0.0);
      float planetLat = (planetSurface.x+planetSurface.y)*0.0005;
      vec3 planetCol = mix(1.3*vec3(0.9, 0.8, 0.7), 0.3*vec3(0.9, 0.8, 0.7), pow(psin(planetLat+1.0)*psin(sqrt(2.0)*planetLat+2.0)*psin(sqrt(3.5)*planetLat+3.0), 0.5));

      vec3 final = vec3(0.0);

      final += step(0.0, si.x)*pow(planetDiff, 0.75)*planetCol*smoothstep(-0.075, 0.0, rd.y)*smoothstep(0.0, 0.1, planetBorder);

      final += skyCol + sunCol + smallSunCol + dust;

      return final;
    }

    vec3 getColor(vec3 ro, vec3 rd) {
      int max_iter = 0;
      vec3 skyCol = skyColor(ro, rd);
      vec3 col = vec3(0);

      float d = march(ro, rd, max_iter);

      if (d < MAX_DISTANCE)   {
        vec3 sunDir = sunDirection();
        vec3 osunDir = sunDir*vec3(-1.0, .0, -1.0);
        vec3 p = ro + d*rd;

        vec3 normal = normal(p.xz, d);

        float amb = 0.2;

        float dif1 = max(0.0, dot(sunDir, normal));
        vec3 shd1 = sunCol2*mix(amb, 1.0, pow(dif1, 0.75));

        float dif2 = max(0.0, dot(osunDir, normal));
        vec3 shd2 = sunCol1*mix(amb, 1.0, pow(dif2, 0.75));

        vec3 ref = reflect(rd, normal);
        vec3 rcol = skyColor(p, ref);

        col = mountainColor*amb*skyCol3;
        col += mix(shd1, shd2, -0.5)*mountainColor;
        float fre = max(dot(normal, -rd), 0.0);
        fre = pow(1.0 - fre, 5.0);
        col += rcol*fre*0.5;
        col += (1.0*p.y);
        col = tanh(col);
        col = mix(col, skyCol, smoothstep(0.5*MAX_DISTANCE, 1.0*MAX_DISTANCE, d));

      } else {
        col = skyCol;
      }

    //  col += vec3(1.1, 0.0, 0.0)* smoothstep(0.25, 1.0,(float(max_iter)/float(MAX_ITER)));
      return col;
    }

    vec3 getSample1(vec2 p, float time) {
      float off = 0.5*iTime;
      vec3 ro  = vec3(0.5, 1.0-0.25, -2.0 + off);
      vec3 la  = ro + vec3(0.0, -0.30,  2.0);
      vec3 ww = normalize(la - ro);
      vec3 uu = normalize(cross(vec3(0.0,1.0,0.0), ww));
      vec3 vv = normalize(cross(ww, uu));
      vec3 rd = normalize(p.x*uu + p.y*vv + 2.0*ww);
      vec3 col = getColor(ro, rd)  ;

      return col;
    }

    vec3 getSample2(vec2 p, float time) {
      p.y-=time*0.25;
      float h = height(p, 0.0);
      vec3 n = normal(p, 0.0);
      vec3 lp = vec3(10.0, -1.2, 0.0);
      vec3 ld = normalize(vec3(p.x, h, p.y)- lp);
      float d = max(dot(ld, n), 0.0);
      vec3 col = vec3(0.0);
      col = vec3(1.0)*(h+0.1);
      col += vec3(1.5)*pow(d, 0.75);

      return col;
    }

    void mainImage(out vec4 fragColor, vec2 fragCoord) {
      vec2 q = fragCoord.xy/iResolution.xy;
      vec2 p = -1.0 + 2.0*q;
      p.x *= iResolution.x/iResolution.y;
      vec3 col = getSample1(p, iTime);
      fragColor = vec4(col, 1.0);
    }
    """

    src_dw = """
    ///////////////////  Desktop Wallpaper
    // Desktop Wallpaper, fragment shader by movAX13h, Nov.2015

    #define INVADERS

    vec3 color = vec3(0.2, 0.42, 0.68); // blue 1
    //vec3 color = vec3(0.1, 0.3, 0.6); // blue 2
    //vec3 color = vec3(0.6, 0.1, 0.3); // red
    //vec3 color = vec3(0.1, 0.6, 0.3); // green

    float width = 24.0;

    float rand(float x) { return fract(sin(x) * 4358.5453); }
    float rand(vec2 co) { return fract(sin(dot(co.xy ,vec2(12.9898,78.233))) * 3758.5357); }

    #ifdef INVADERS
    float invader(vec2 p, float n)
    {
        p.x = abs(p.x);
        p.y = -floor(p.y - 5.0);
        return step(p.x, 2.0) * step(1.0, floor(mod(n/(exp2(floor(p.x + p.y*3.0))),2.0)));
    }
    #endif

    void mainImage(out vec4 fragColor, in vec2 fragCoord)
    {
        if (iMouse.z > 0.5) color = vec3(0.5, 0.3, 0.1);

        vec2 p = fragCoord.xy;
        vec2 uv = p / iResolution.xy - 0.5;

        float id1 = rand(floor(p.x / width));
        float id2 = rand(floor((p.x - 1.0) / width));

        float a = 0.3*id1;
        a += 0.1*step(id2, id1 - 0.08);
        a -= 0.1*step(id1 + 0.08, id2);
        a -= 0.3*smoothstep(0.0, 0.7, length(uv));

        #ifdef INVADERS
        //p.y += 20.0*iTime;
        float r = rand(floor(p/8.0));
        float inv = invader(mod(p,8.0)-4.0, 809999.0*r);
        a += (0.06 + max(0.0, 0.2*sin(10.0*r*iTime))) * inv * step(id1, 0.1);
        #endif

        fragColor = vec4(color+a, 1.0);
    }
    """

    src_if = """
    ///////////////////  ice and fire
    /* ice and fire, by mattz
       License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
       Demonstrate triangulation of jittered triangular lattice.
    */
    const float s3 = 1.7320508075688772;
    const float i3 = 0.5773502691896258;

    const mat2 tri2cart = mat2(1.0, 0.0, -0.5, 0.5*s3);
    const mat2 cart2tri = mat2(1.0, 0.0, i3, 2.0*i3);

    //////////////////////////////////////////////////////////////////////
    // cosine based palette 
    // adapted from https://www.shadertoy.com/view/ll2GD3

    vec3 pal( in float t ) {

        const vec3 a = vec3(0.5);
        const vec3 b = vec3(0.5);
        const vec3 c = vec3(0.8, 0.8, 0.5);
        const vec3 d = vec3(0, 0.2, 0.5);

        return clamp(a + b*cos( 6.28318*(c*t+d) ), 0.0, 1.0);
    }

    //////////////////////////////////////////////////////////////////////
    // from https://www.shadertoy.com/view/4djSRW

    #define HASHSCALE1 .1031
    #define HASHSCALE3 vec3(443.897, 441.423, 437.195)

    float hash12(vec2 p) {
        vec3 p3  = fract(vec3(p.xyx) * HASHSCALE1);
        p3 += dot(p3, p3.yzx + 19.19);
        return fract((p3.x + p3.y) * p3.z);   
    }

    vec2 hash23(vec3 p3) {
        p3 = fract(p3 * HASHSCALE3);
        p3 += dot(p3, p3.yzx+19.19);
        return fract((p3.xx+p3.yz)*p3.zy);
    }

    //////////////////////////////////////////////////////////////////////
    // compute barycentric coordinates from point differences
    // adapted from https://www.shadertoy.com/view/lslXDf

    vec3 bary(vec2 v0, vec2 v1, vec2 v2) {
        float inv_denom = 1.0 / (v0.x * v1.y - v1.x * v0.y);
        float v = (v2.x * v1.y - v1.x * v2.y) * inv_denom;
        float w = (v0.x * v2.y - v2.x * v0.y) * inv_denom;
        float u = 1.0 - v - w;
        return vec3(u,v,w);
    }

    //////////////////////////////////////////////////////////////////////
    // distance to line segment from point differences

    float dseg(vec2 xa, vec2 ba) {
        return length(xa - ba*clamp(dot(xa, ba)/dot(ba, ba), 0.0, 1.0));
    }

    //////////////////////////////////////////////////////////////////////
    // generate a random point on a circle from 3 integer coords (x, y, t)

    vec2 randCircle(vec3 p) {
        
        vec2 rt = hash23(p);
        
        float r = sqrt(rt.x);
        float theta = 6.283185307179586 * rt.y;

        return r*vec2(cos(theta), sin(theta));

    }

    //////////////////////////////////////////////////////////////////////
    // make a time-varying cubic spline at integer coords p that stays
    // inside a unit circle

    vec2 randCircleSpline(vec2 p, float t) {

        // standard catmull-rom spline implementation
        float t1 = floor(t);
        t -= t1;

        vec2 pa = randCircle(vec3(p, t1-1.0));
        vec2 p0 = randCircle(vec3(p, t1));
        vec2 p1 = randCircle(vec3(p, t1+1.0));
        vec2 pb = randCircle(vec3(p, t1+2.0));

        vec2 m0 = 0.5*(p1 - pa);
        vec2 m1 = 0.5*(pb - p0);

        vec2 c3 = 2.0*p0 - 2.0*p1 + m0 + m1;
        vec2 c2 = -3.0*p0 + 3.0*p1 - 2.0*m0 - m1;
        vec2 c1 = m0;
        vec2 c0 = p0;

        return (((c3*t + c2)*t + c1)*t + c0) * 0.8;
    }

    //////////////////////////////////////////////////////////////////////
    // perturbed point from index

    vec2 triPoint(vec2 p) {
        float t0 = hash12(p);
        return tri2cart*p + 0.45*randCircleSpline(p, 0.15*iTime + t0);
    }

    //////////////////////////////////////////////////////////////////////
    // main shading function. inputs:
    // 
    //   p - current pixel location in scene
    //
    //   tfloor - integer grid coordinates of bottom-left triangle vertex
    //
    //   t0, t1, t2 - displaced cartesian coordinates (xy) and integer
    //                grid offsets (zw) of triangle vertices, relative
    //                to tfloor
    //
    //   scl - pixel size in scene units
    //
    //   cw - pixel accumulator. xyz are rgb color pre-multiplied by
    //        weights, and w is total weight.
    //

    void tri_color(in vec2 p, 
                   in vec4 t0, in vec4 t1, in vec4 t2, 
                   in float scl, 
                   inout vec4 cw) {

        // get differences relative to vertex 0
        vec2 p0 = p - t0.xy;
        vec2 p10 = t1.xy - t0.xy;
        vec2 p20 = t2.xy - t0.xy;

        // get barycentric coords
        vec3 b = bary(p10, p20, p0);

        // distances to line segments
        float d10 = dseg(p0, p10);
        float d20 = dseg(p0, p20);
        float d21 = dseg(p - t1.xy, t2.xy - t1.xy);

        // unsigned distance to triangle boundary
        float d = min(min(d10, d20), d21);

        // now signed distance (negative inside, positive outside)
        d *= -sign(min(b.x, min(b.y, b.z))); 

        // only wory about coloring if close enough
        if (d < 0.5*scl) {

            //////////////////////////////////////////////////
            // generate per-vertex palette entries

            // sum of all integer grid indices
            vec2 tsum = t0.zw + t1.zw + t2.zw;

            // generate unique random number in [0, 1] for each vertex of
            // this triangle
            vec3 h_tri = vec3(hash12(tsum + t0.zw),
                              hash12(tsum + t1.zw),
                              hash12(tsum + t2.zw));

            //////////////////////////////////////////////////
            // now set up the "main" triangle color:
            
            // get the cartesian centroid of this triangle
            vec2 pctr = (t0.xy + t1.xy + t2.xy) / 3.0;

            // angle of scene-wide color gradient
            float theta = 1.0 + 0.01*iTime;
            vec2 dir = vec2(cos(theta), sin(theta));

            // how far are we along gradient?
            float grad_input = dot(pctr, dir) - sin(0.05*iTime);

            // h0 varies smoothly from 0 to 1
            float h0 = sin(0.7*grad_input)*0.5 + 0.5;

            // now the per-vertex random numbers are all biased towards h
            // (still in [0, 1] range tho)
            h_tri = mix(vec3(h0), h_tri, 0.4);

            //////////////////////////////////////////////////
            // final color accumulation
            
            // barycentric interpolation of per-vertex palette indices
            float h = dot(h_tri, b);

            // color lookup
            vec3 c = pal(h);

            // weight for anti-aliasing is 0.5 at border, 0 just outside,
            // 1 just inside
            float w = smoothstep(0.5*scl, -0.5*scl, d);

            // add to accumulator
            cw += vec4(w*c, w);
        }
    }

    //////////////////////////////////////////////////////////////////////

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {

        float scl = 4.1 / iResolution.y;

        // get 2D scene coords
        vec2 p = (fragCoord - 0.5 - 0.5*iResolution.xy) * scl;

        // get triangular base coords
        vec2 tfloor = floor(cart2tri * p + 0.5);

        // precompute 9 neighboring points
        vec2 pts[9];

        for (int i=0; i<3; ++i) {
            for (int j=0; j<3; ++j) {
                pts[3*i+j] = triPoint(tfloor + vec2(i-1, j-1));
            }
        }

        // color accumulator
        vec4 cw = vec4(0);

        // for each of the 4 quads:
        for (int i=0; i<2; ++i) {
            for (int j=0; j<2; ++j) {

                // look at lower and upper triangle in this quad
                vec4 t00 = vec4(pts[3*i+j  ], tfloor + vec2(i-1, j-1));
                vec4 t10 = vec4(pts[3*i+j+3], tfloor + vec2(i,   j-1));
                vec4 t01 = vec4(pts[3*i+j+1], tfloor + vec2(i-1, j));
                vec4 t11 = vec4(pts[3*i+j+4], tfloor + vec2(i,   j));

                // lower
                tri_color(p, t00, t10, t11, scl, cw);

                // upper
                tri_color(p, t00, t11, t01, scl, cw);
            }
        }

        // final pixel color
        fragColor = cw / cw.w;
    }
    """

    src_vg = """
    ///////////////////  Voronoi Gradient
    // v1.2

    #define t iTime*2.
    #define SIZE 30.

    #define col1 vec3(193.,41.,46.)/255.
    #define col2 vec3(241.,211.,2.)/255.

    vec2 ran(vec2 uv) {
        uv *= vec2(dot(uv,vec2(127.1,311.7)),dot(uv,vec2(227.1,521.7)) );
        return 1.0-fract(tan(cos(uv)*123.6)*3533.3)*fract(tan(cos(uv)*123.6)*3533.3);
    }
    vec2 pt(vec2 id) {
        return sin(t*(ran(id+.5)-0.5)+ran(id-20.1)*8.0)*0.5;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord-.5*iResolution.xy)/iResolution.x;
        vec2 off = iTime/vec2(50.,30.);
        uv += off;
        uv *= SIZE;
        
        vec2 gv = fract(uv)-.5;
        vec2 id = floor(uv);
        
        float mindist = 1e9;
        vec2 vorv;
        for(float i=-1.;i<=1.;i++) {
            for(float j=-1.;j<=1.;j++) { 
                vec2 offv = vec2(i,j);
                float dist = length(gv+pt(id+offv)-offv);
                if(dist<mindist){
                    mindist = dist;
                    vorv = (id+pt(id+offv)+offv)/SIZE-off;
                }
            }
        }
        
        vec3 col = mix(col1,col2,clamp(vorv.x*2.2+vorv.y,-1.,1.)*0.5+0.5);
        
        fragColor = vec4(col,1.0);

        /*
        fragColor += vec4(vec3(smoothstep(0.08,0.05,gv.x+pt(id).x)),0.0);
        fragColor -= vec4(vec3(smoothstep(0.05,0.03,gv.x+pt(id).x)),0.0);
        */
    }
    """

    src_pr = """
    ///////////////////  Pixelated RGB with shadows

    float rand(vec2 co){ return fract(sin(dot(co.xy ,vec2(12.9898,78.233))) * 43758.5453); } // random noise

    float getCellBright(vec2 id) {
        return sin((iTime+2.)*rand(id)*2.)*.5+.5; // returns 0. to 1.
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
        float mx = max(iResolution.x, iResolution.y);
        vec2 uv = fragCoord.xy / mx;
        
        float time = iTime*.5;
        
        uv *= 30.; // grid size

        vec2 id = floor(uv); // id numbers for each "cell"
        vec2 gv = fract(uv)-.5; // uv within each cell, from -.5 to .5

        vec3 color = vec3(0.);
        
        float randBright = getCellBright(id);
        
        vec3 colorShift = vec3(rand(id)*.1); // subtle random color offset per "cell"
        
        color = 0.6 + 0.5*cos(time + (id.xyx*.1) + vec3(4,2,1) + colorShift); // RGB with color offset
        
        float shadow = 0.;
        shadow += smoothstep(.0, .7,  gv.x*min(0., (getCellBright(vec2(id.x-1., id.y)) - getCellBright(id)))); // left shadow
        shadow += smoothstep(.0, .7, -gv.y*min(0., (getCellBright(vec2(id.x, id.y+1.)) - getCellBright(id)))); // top shadow
        
        color -= shadow*.4;
        
        color *= 1. - (randBright*.2);
        
        fragColor = vec4(color, 1.0);
    }
    """

    src_ps3 = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.318, 0.831, 1.0);
    const vec3 bottom = vec3(0.094, 0.141, 0.424);
    const float widthFactor = 1.5;

    vec3 calcSine(vec2 uv, float speed, 
                  float frequency, float amplitude, float shift, float offset,
                  vec3 color, float width, float exponent, bool dir)
    {
        float angle = iTime * speed * frequency * -1.0 + (shift + uv.x) * 2.0;
        
        float y = sin(angle) * amplitude + offset;
        float clampY = clamp(0.0, y, y);
        float diffY = y - uv.y;
        
        float dsqr = distance(y, uv.y);
        float scale = 1.0;
        
        if(dir && diffY > 0.0)
        {
            dsqr = dsqr * 4.0;
        }
        else if(!dir && diffY < 0.0)
        {
            dsqr = dsqr * 4.0;
        }
        
        scale = pow(smoothstep(width * widthFactor, 0.0, dsqr), exponent);
        
        return min(color * scale, color);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec3 color = vec3(mix(bottom, top, uv.y));

        color += calcSine(uv, 0.2, 0.20, 0.2, 0.0, 0.5,  vec3(0.3, 0.3, 0.3), 0.1, 15.0,false);
        color += calcSine(uv, 0.4, 0.40, 0.15, 0.0, 0.5, vec3(0.3, 0.3, 0.3), 0.1, 17.0,false);
        color += calcSine(uv, 0.3, 0.60, 0.15, 0.0, 0.5, vec3(0.3, 0.3, 0.3), 0.05, 23.0,false);

        color += calcSine(uv, 0.1, 0.26, 0.07, 0.0, 0.3, vec3(0.3, 0.3, 0.3), 0.1, 17.0,true);
        color += calcSine(uv, 0.3, 0.36, 0.07, 0.0, 0.3, vec3(0.3, 0.3, 0.3), 0.1, 17.0,true);
        color += calcSine(uv, 0.5, 0.46, 0.07, 0.0, 0.3, vec3(0.3, 0.3, 0.3), 0.05, 23.0,true);
        color += calcSine(uv, 0.2, 0.58, 0.05, 0.0, 0.3, vec3(0.3, 0.3, 0.3), 0.2, 15.0,true);

        fragColor = vec4(color,1.0);
    }
    """

    src_ih = """
    ///////////////////  Infinite hexes background

    // License CC0: Infinite hexes background
    //  A few weeks ago I tried to recreate a background of a twitch stream
    //  The initial estimate was: "Should be easy!"
    //  I spent many evenings tinkering with the shadows as I had the idea
    //  that no raytracing is needed because it "Should be easy!" so I just fake the shadows.
    //  In the end I stopped developing the shader disatisfied.
    //  Coming back a few weeks later I now thinks it looks kind of ok.
    //  It is a bit dark but it is intended as a background effect.
    //  The shadows are not perfect but passable. 
    //  So I thought I just publish it. 
    //  The code is hackish and I have no memory how it works anymore except it annoys me :)
    //
    //  Trust the process

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))
    #define PI          3.141592654
    #define TAU         (2.0*PI)

    // https://lists.office.com/Images/72f988bf-86f1-41af-91ab-2d7cd011db47/89ec7e89-f5c4-4b93-9c25-3f75e5220995/T7THIPBZ0Z2YSIOMG8GGIG3OWC/615d356e-0a16-4105-814d-f0408c7d5efb
    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    float sRGB(float t) { return mix(1.055*pow(t, 1./2.4) - 0.055, 12.92*t, step(t, 0.0031308)); }
    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(in vec3 c) { return vec3 (sRGB(c.x), sRGB(c.y), sRGB(c.z)); }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
      //  Found this somewhere on the interwebs
      //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: Unknown, found: don't remember
    float hash(vec2 co) {
      return fract(sin(dot(co.xy ,vec2(12.9898,58.233))) * 13758.5453);
    }

    // License: Unknown, author: Martijn Steinrucken, found: https://www.youtube.com/watch?v=VmrIDyYiJBA
    vec2 hextile(inout vec2 p) {
      // See Art of Code: Hexagonal Tiling Explained!
      // https://www.youtube.com/watch?v=VmrIDyYiJBA
      const vec2 sz       = vec2(1.0, sqrt(3.0));
      const vec2 hsz      = 0.5*sz;

      vec2 p1 = mod(p, sz)-hsz;
      vec2 p2 = mod(p - hsz, sz)-hsz;
      vec2 p3 = dot(p1, p1) < dot(p2, p2) ? p1 : p2;
      vec2 n = ((p3 - p + hsz)/sz);
      p = p3;

      n -= vec2(0.5);
      // Rounding to make hextile 0,0 well behaved
      return round(n*2.0)*0.5;
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/www/articles/distfunctions2d/distfunctions2d.htm
    float hexagon(vec2 p, float r) {
      const vec3 k = vec3(-0.866025404,0.5,0.577350269);
      p = abs(p);
      p -= 2.0*min(dot(k.xy,p),0.0)*k.xy;
      p -= vec2(clamp(p.x, -k.z*r, k.z*r), r);
      return length(p)*sign(p.y);
    }

    float shape(vec2 p) {
      return hexagon(p.yx, 0.4)-0.075;
    }

    float cellHeight(float h) {
      return 0.05*2.0*(-h);
    }

    vec3 cell(vec2 p, float h) {
      float hd = shape(p);

      const float he = 0.0075*2.0;
      float aa = he;
      float hh = -he*smoothstep(aa, -aa, hd);
      
      return vec3(hd, hh, cellHeight(h));
    }

    float height(vec2 p, float h) {
      return cell(p, h).y;
    }

    vec3 normal(vec2 p, float h) {
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy, h) - height(p - e.xy, h);
      n.y = height(p + e.yx, h) - height(p - e.yx, h);
      n.z = 2.0*e.x;
      
      return normalize(n);
    }

    vec3 planeColor(vec3 ro, vec3 rd, vec3 lp, vec3 pp, vec3 pnor, vec3 bcol, vec3 pcol) {
      vec3  ld = normalize(lp-pp);
      float dif  = pow(max(dot(ld, pnor), 0.0), 1.0);
      vec3 col = pcol;
      col = mix(bcol, col, dif);
      return col;
    }

    const mat2 rots[6] = mat2[](
        ROT(0.0*TAU/6.0)
      , ROT(1.0*TAU/6.0)
      , ROT(2.0*TAU/6.0)
      , ROT(3.0*TAU/6.0)
      , ROT(4.0*TAU/6.0)
      , ROT(5.0*TAU/6.0)
    ); 

    const vec2 off = vec2(1.0, 0.0);

    const vec2 offs[6] = vec2[](
        off*rots[0]
      , off*rots[1]
      , off*rots[2]
      , off*rots[3]
      , off*rots[4]
      , off*rots[5]
      );
      
    float cutSlice(vec2 p, vec2 off) {
      // A bit like this but unbounded
      // https://www.shadertoy.com/view/MlycD3
      p.x = abs(p.x);
      off.x *= 0.5; 

      vec2 nn = normalize(vec2(off));
      vec2 n  = vec2(nn.y, -nn.x);

      float d0 = length(p-off);
      float d1 = -(p.y-off.y);
      float d2 = dot(n, p);
      
      bool b = p.x > off.x && (dot(nn, p)-dot(nn, off)) < 0.0;
      
      return b ? d0 : max(d1, d2);
    }

    float hexSlice(vec2 p, int n) {
      n = 6-n;
      n = n%6;
      p *= rots[n];
      p = p.yx;
      const vec2 dim  = vec2((0.5)*2.0/sqrt(3.0), (0.5));
      return cutSlice(p, dim);
    }

    vec3 effect(vec2 p, vec2 q) {
      const float z = 0.327;
      float aa = 2.0/(z*RESOLUTION.y);
      
      p.yx = p;
      
      vec3 lp = vec3(3.0, 0.0, 1.0);
      
      p -= vec2(0.195, 0.);
      p /= z;

      float toff = 0.2*TIME;
      p.x += toff;
      lp.x += toff;

      vec2 hp  = p;
      vec2 hn  = hextile(hp);
      float hh = hash(hn);
      vec3 c   = cell(hp, hh);
      float cd = c.x;
      float ch = c.z;  

      vec3 fpp = vec3(p, ch);
      vec3 bpp = vec3(p, 0.0);

      vec3 ro = vec3(0.0, 0.0, 1.0);
      vec3 rd = normalize(fpp-ro);

      vec3  bnor = vec3(0.0, 0.0, 1.0);
      vec3  bdif = lp-bpp;
      float bl2  = dot(bdif, bdif);

      vec3  fnor = normal(hp, hh);
      vec3  fld  = normalize(lp-fpp); 

      float sf = 0.0;

      for (int i = 0; i < 6; ++i) {
        vec2  ioff= offs[i];
        vec2  ip  = p+ioff;
        vec2  ihn = hextile(ip);
        float ihh = hash(ihn);
        float ich = cellHeight(ihh);
        float iii = (ich-ch)/fld.z;
        vec3  ipp = vec3(hp, ch)+iii*fld;
        
        float hsd = hexSlice(ipp.xy, i);
        if (ich > ch) {
          sf += exp(-20.0*tanh_approx(1.0/(10.0*iii))*max(hsd+0., 0.0));
        }
      }

      const float sat = 0.23;
      vec3 bpcol = planeColor(ro, rd, lp, bpp, bnor, vec3(0.0), HSV2RGB(vec3(240.0/36.0, sat, 0.14)));
      vec3 fpcol = planeColor(ro, rd, lp, fpp, fnor, bpcol, HSV2RGB(vec3(240.0/36.0, sat, 0.19)));

      vec3 col = bpcol;
      col = mix(col, fpcol, smoothstep(aa, -aa, cd));
      col *= 1.0-tanh_approx(sf);

      float fo = exp(-0.025*max(bl2-0., 0.0));
      col *= fo;
      col = mix(bpcol, col, fo);


      return col;
    }

    void mainImage(out vec4 fragColor, in vec2 fragCoord) {
      vec2 q = fragCoord/RESOLUTION.xy; 
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      
      vec3 col = effect(p, q);
      col = sRGB(col);
      
      fragColor = vec4(col,1.0);
    }
    """

    src_fp = """
    /////////////////// Floating Playstation Shapes

    // Common parameters:
    #define SHAPE_SIZE 0.06
    #define BLUR 0.001
    #define VERTICAL_TRAVEL 0.1
    #define SPEED_TRAVEL 0.6
    #define SPEED_ROTATION 1.
    #define ALPHA .7

    // Colors
    #define DARK_BLUE vec3(16./255.,50./255.,66./255.)
    #define LIGHT_BLUE vec3(34./255.,76./255.,114./255.)
    #define SHAPE_GRAY vec3(93./255.,119./255.,137./255.)

    // Only applies to the circle and square
    #define INNER_CUTOUT_SCALE 0.7

    // The taper-off point for the triangle to be equilateral
    const float EQUILATERAL_HEIGHT =
            sqrt(pow(SHAPE_SIZE,2.) - pow(SHAPE_SIZE/2.,2.))
            - SHAPE_SIZE/2.;

    // NEW on Jul-24-2021: grid based rendering to improve performance
    // the old way is pretty terrible in hindsight
    #define NEW_RENDERER 1

    // Old renderer parameter:
    // set to an ammount similar to density 12 on the new renderer
    // so you can see the performance improvement
    // (at least I can see the difference on my 6 year old Macbook Air)
    #define SHAPE_AMOUNT 300.

    // New renderer parameters:
    #define DENSITY 12.
    // see the note in the main function
    #define PRESERVE_VERTICAL_TRAVEL 1

    // Helper functions grabbed from the internet
    float rand(vec2 co) {
        return fract(sin(dot(co.xy ,vec2(12.9898,78.233)))
            *43758.5453);
    }

    vec2 N22(vec2 p) {
        vec3 a = fract(p.xyx*vec3(123.34,234.34,345.65));
        a += dot(a, a+34.45);
        return fract(vec2(a.x*a.y,a.y*a.z));
    }

    // https://gist.github.com/companje/29408948f1e8be54dd5733a74ca49bb9
    float map(float value, float min1, float max1,
            float min2, float max2) {
        return min2 + (value - min1)*(max2 -min2)
            /(max1 - min1);
    }

    mat2 rotate(float angle) {
        return mat2(cos(angle),-sin(angle),
            sin(angle),cos(angle));
    }

    // Background gradient
    vec3 background(vec2 uv) {
        const float GRAD_START = 0.25, GRAD_STOP = 0.95;
        return mix(LIGHT_BLUE,DARK_BLUE,
            smoothstep(GRAD_START,GRAD_STOP,uv.y));
    }

    // Solid helper shapes
    float box(vec2 uv, float left, float right,
            float down, float up, float blur) {
        return smoothstep(left,left+blur,uv.x)
            *smoothstep(right,right-blur,uv.x)
            *smoothstep(down,down+blur,uv.y)
            *smoothstep(up,up-blur,uv.y);
    }

    float box(vec2 uv, float lowerBound, float upperBound,
            float blur) {
        return box(uv,lowerBound,upperBound,
                   lowerBound,upperBound,blur);
    }

    float triangleSolid(vec2 uv, float size, float height,
            float blur) {
        float sides = map(uv.y,-size/2.,height,size/2.,0.);
        return box(uv,-sides,sides,-size/2.,size/2.,blur);    
    }

    // Main shapes
    float circle(vec2 uv, float size, float blur, float alpha) {
        float radius = size/2.;
        return alpha*(smoothstep(radius+blur,radius,length(uv))
            - smoothstep(INNER_CUTOUT_SCALE*radius+blur,
                         INNER_CUTOUT_SCALE*radius,
                         length(uv)));
    }

    float X(vec2 uv, float size, float blur, float alpha) {
        float lower = -size/2., upper = size/2.;
        return alpha*(box(uv,lower,upper,lower/5.,upper/5.,blur)
            + box(uv,lower/5.,upper/5.,lower,upper,blur)
            - box(uv,lower/5.,upper/5.,blur));
    }

    float triangle(vec2 uv, float size, float height,
            float blur, float alpha) {
        vec2 innerCoord = uv*2.;
        const float BASE_SIZE = 0.05, SCALING_FACTOR = 0.01;
        innerCoord.y += SHAPE_SIZE/BASE_SIZE*SCALING_FACTOR;
        return alpha*(triangleSolid(uv,size,height,blur)
            - triangleSolid(innerCoord,size,height,blur));
    }

    float square(vec2 uv, float size, float blur, float alpha) {
        return alpha*(box(uv,-size/2.,size/2.,blur)
            - box(uv,-INNER_CUTOUT_SCALE*size/2.,
                  INNER_CUTOUT_SCALE*size/2.,blur));
    }

    vec2 sway(vec2 uv, vec2 start, float vertTravel,
            float timeShift) {
        return vec2(uv.x-start.x,uv.y-start.y
                    - vertTravel*sin(SPEED_TRAVEL
                                     *iTime-timeShift));
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
        vec2 uv = fragCoord/iResolution.xy;
        float ASPECT_RATIO = iResolution.x/iResolution.y;
        uv.x *= ASPECT_RATIO;

        vec3 col = background(uv);

        #if NEW_RENDERER
        uv *= DENSITY;
        vec2 xy = fract(uv)-.5,  // point within a grid cell
             id = floor(uv),     // the grid cell we are in
             cid = vec2(0.);     // the id adjusted for the actual location of the cell
        /*
        Here we see which shapes are in this cell and the surrounding
        cells (the shapes nearby) and draw their value for this pixel.
        Unfortunately we cannot increase the shape density
        while maintaining the vertical travel of the shapes
        without having shapes from far-away grid cells "come into"
        our grid cell and not being being drawn since we only check
        nearby cells for shapes.
        This introduces clipping on the shapes which can only be fixed by
        increasing the number of neighboring grid cells checked
        per iteration, which unfortunately hurts performance.
        We already need slightly more vertical grid cells with the
        default settings because the shapes were already traveling
        too far.
        */
        #if PRESERVE_VERTICAL_TRAVEL
        // I did a quick check at density ~30 with default size
        // with these start/end values but they aren't perfect
        const vec2 startValue = vec2(-1.-DENSITY/30.,-2.-DENSITY/14.),
                   endValue = vec2(1.+DENSITY/60.,1.+DENSITY/10.);
        #else
        const vec2 startValue = vec2(-1.,-2.),
                   endValue = vec2(1.);
        #endif
        for(float yCell=startValue.y; yCell <= endValue.y; yCell++) {
            for(float xCell=startValue.x; xCell <= endValue.x; xCell++) {
                vec2 off = vec2(xCell,yCell);
                cid = id+off;
                vec2 origin = off+N22(cid);
                
                // big/random multipliers to spread out shape types
                float shapeID = 400.*rand(cid)+2.526*cid.y;
                
                origin = sway(origin,vec2(0.),
                              #if PRESERVE_VERTICAL_TRAVEL 
                              DENSITY*
                              #endif
                              VERTICAL_TRAVEL,shapeID);

                // rotate and scale the coordinate system for the shape
                // which we previously moved vertically based on time
                vec2 pointRotated = 1./DENSITY*(origin-xy)*rotate(sin(SPEED_ROTATION*iTime-shapeID));
                switch(int(mod(shapeID,4.))) {
                case 0:
                default:
                    col = mix(col,SHAPE_GRAY,
                              X(pointRotated,SHAPE_SIZE,BLUR,ALPHA));
                    break;
                case 1:
                    col = mix(col,SHAPE_GRAY,
                              circle(pointRotated,SHAPE_SIZE,BLUR,ALPHA));
                    break;
                case 2:
                    col = mix(col,SHAPE_GRAY,
                              triangle(pointRotated,SHAPE_SIZE,
                                       EQUILATERAL_HEIGHT,
                                       BLUR,ALPHA));
                    break;
                case 3:
                    col = mix(col,SHAPE_GRAY,
                              square(pointRotated,SHAPE_SIZE,BLUR,ALPHA));
                    break;
                }
            }
        }
        #else
        for(float i = 0.; i < SHAPE_AMOUNT; i++) {
            vec2 seed = vec2(i,i);
            vec2 cord = vec2(rand(seed),rand(-.5*seed));
            cord.x *= ASPECT_RATIO;
            vec2 xy = sway(uv,cord,VERTICAL_TRAVEL,i);
            switch(int(mod(i,4.))) {
                case 0:
                    xy *= rotate(sin(SPEED_ROTATION*iTime-i));
                    col = mix(col,SHAPE_GRAY,
                              X(xy,SHAPE_SIZE,BLUR,ALPHA));
                    break;
                case 1:
                    col = mix(col,SHAPE_GRAY,
                              circle(xy,SHAPE_SIZE,BLUR,ALPHA));
                    break;
                case 2:
                    xy *= rotate(sin(SPEED_ROTATION*iTime-i));
                    col = mix(col,SHAPE_GRAY,
                              triangle(xy,SHAPE_SIZE,
                                       EQUILATERAL_HEIGHT,
                                       BLUR,ALPHA));
                    break;
                case 3:
                default:
                    xy *= rotate(sin(SPEED_ROTATION*iTime-i));
                    col = mix(col,SHAPE_GRAY,
                              square(xy,SHAPE_SIZE,BLUR,ALPHA));
                    break;
            }
        }
        #endif
        
        fragColor = vec4(col,1.0);
    }
    """

    src_amb = """
    /////////////////// Abstract Movement Background

    #define BackgroundColor vec3(0.91765, 0.88627,0.82745)
    #define Layer1Color vec3(0.95686, 0.27451, 0.16078)
    #define Layer2Color vec3(0.10980, 0.12157, 0.27843)
    #define Layer3Color vec3(0.18824, 0.20000, 0.52157)

    #define degToRad 0.01745329252

    float Rand(float i)
    {
        return fract(sin(i * 23325.) * 35543.);
    }

    vec4 Rand4(float i)
    {
        return fract(sin(i * vec4(23325.,53464.,76543.,12312)) * vec4(35543.,63454.,23454.,87651));
    }

    mat2 Rot(float a)
    {
        float s = sin(a);
        float c = cos(a);
        return mat2(c, -s, s, c);
    }

    float DrawLine(in vec2 uv, in vec2 a, in vec2 b )
    {
        vec2 ba = b-a;
        vec2 pa = uv-a;
        float h =clamp( dot(pa,ba)/dot(ba,ba), 0.0, 1.0 );
        return length(pa-h*ba);
    }

    float DrawLineSegment(in vec2 uv, float linesCount, float speed, float verticalAmplitude, float segmentSeed)
    {
        float segmentMask = 0.;
        float iterationStep = 1. / linesCount;
        float t = iTime * speed *.1;
        float horizontalAmplitude = 3.5;
        vec2 lineWidthRange = vec2(0.2,1.5);
        vec2 lineSizeRange = vec2(0.005,0.035);
        float seedBase = Rand(segmentSeed);

        for(float i = 0.; i <= 1.; i += iterationStep)
        {
            float unitSpeed = mix(0.5,2.0,Rand(i));
            float seed = t * unitSpeed + i + seedBase;
            float it = fract(seed);
            vec4 iHash = Rand4(i);
            float normit = it*2. - 1.;
            float lineWidth = mix(lineWidthRange.x, lineWidthRange.y, pow(iHash.y,2.));
            vec2 ap = vec2(-horizontalAmplitude * normit, iHash.x * verticalAmplitude);
            vec2 bp = ap + vec2(lineWidth, 0.);
            float lineSegmentDist = DrawLine(uv,ap,bp);
            float lineSize = mix(lineSizeRange.x, lineSizeRange.y, pow(iHash.z,4.));
            segmentMask += smoothstep(lineSize + 0.002, lineSize -0.002, lineSegmentDist);
        }

        return clamp(segmentMask,0.,1.);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (2.0* fragCoord- iResolution.xy)/iResolution.y;
        uv *= Rot(degToRad * -35.);

        vec3 col = mix(Layer1Color, BackgroundColor,smoothstep(-0.055,-0.05, uv.y));
        col = mix(Layer2Color, col, smoothstep(-0.655,-0.65,uv.y)); 
        col = mix(Layer3Color, col, smoothstep(-1.305,-1.3,uv.y));
        
        col = mix(col,BackgroundColor, DrawLineSegment(uv - vec2(0.,-0.3), 9., 0.5, 0.35, 0.2));
        col = mix(col,Layer1Color, DrawLineSegment(uv- vec2(0.,0.), 25., -.4, .5, 0.1));
        
        col = mix(col,Layer1Color, DrawLineSegment(uv - vec2(0.,-1.0), 25., -0.4, .45, 0.4));
        col = mix(col,Layer2Color, DrawLineSegment(uv - vec2(0.,-0.65), 25., 0.3, .3, 0.3));
        
        col = mix(col,Layer2Color, DrawLineSegment(uv - vec2(0.,-1.8), 25., 0.3, .55, 0.6));
        col = mix(col,Layer3Color, DrawLineSegment(uv - vec2(0.,-1.3), 25., -0.2, .3, 0.5));

        fragColor = vec4(col,1.0);
    }
    """

    src_dcf = """
    /////////////////// Dark chocolate FBM

    // License CC0: Dark chocolate FBM
    //  Working on a cake related shader and created kind of dark chocolate
    //  background. Nothing unique but different colors than what I usually 
    //  do so sharing.

    #define TIME        iTime
    #define RESOLUTION  iResolution

    #define PI          3.141592654
    #define TAU         (2.0*PI)
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))
    #define TTIME       (TAU*TIME)
    #define DOT2(p)     dot(p, p)

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/smin/smin.htm
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    // License: CC0, author: Mårten Rånge, found: https://github.com/mrange/glsl-snippets
    float pabs(float a, float k) {
      return -pmin(a, -a, k);
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/www/articles/distfunctions2d/distfunctions2d.htm
    float heart(vec2 p) {
      p.y -= -0.6;
      p.x = pabs(p.x, 0.125);

      if( p.y+p.x>1.0 )
          return sqrt(DOT2(p-vec2(0.25,0.75))) - sqrt(2.0)/4.0;
      return sqrt(min(DOT2(p-vec2(0.00,1.00)),
                      DOT2(p-0.5*max(p.x+p.y,0.0)))) * sign(p.x-p.y);
    }

    vec2 mod2_1(inout vec2 p) {
      vec2 n = floor(p + 0.5);
      p = fract(p+0.5)-0.5;
      return n;
    }

    float hf(vec2 p) {  
      p *= 0.25;
      vec2 p0 = p;
      vec2 n0 = mod2_1(p0);
      vec2 p1 = p*vec2(1.0, -1.0)+vec2(0.5, 0.66);
      vec2 n1 = mod2_1(p1);
      const float ss = 0.60;
      float d0 = heart(p0/ss)*ss;
      float d1 = heart(p1/ss)*ss;
      float d = min(d0, d1);
      return tanh_approx(smoothstep(0.0, -0.1,d)*exp(8.0*-d));
    }

    float height(vec2 p) {
      const mat2 rot1 = ROT(1.0);
      float tm = 123.0+TTIME/240.0;
      p += 5.0*vec2(cos(tm), sin(tm*sqrt(0.5)));
      const float aa = -0.45;
      const mat2  pp = (1.0/aa)*rot1;
      float h = 0.0;
      float a = 1.0;
      float d = 0.0;
      for (int i = 0; i < 4; ++i) {
        h += a*hf(p);
        d += a;
        a *= aa;
        p *= pp;
      }  
      const float hf = -0.125;
      return hf*(h/d)+hf;
    }

    vec3 normal(vec2 p) {
      vec2 v;
      vec2 w;
      vec2 e = vec2(4.0/RESOLUTION.y, 0);
      
      vec3 n;
      n.x = height(p + e.xy) - height(p - e.xy);
      n.y = 2.0*e.x;
      n.z = height(p + e.yx) - height(p - e.yx);
      
      return normalize(n);
    }

    vec3 effect(vec2 p, vec2 q) {
      vec2 ppp = p;
      const float s     = 1.0;
      const vec3 lp1    = vec3(1.0, 1.25, 1.0)*vec3(s, 1.0, s);
      const vec3 lp2    = vec3(-1.0, 1.25, 1.0)*vec3(s, 1.0, s);
      const vec3 lcol1  = HSV2RGB(vec3(0.06, 0.9 , .5));
      const vec3 lcol2  = HSV2RGB(vec3(0.05, 0.25, 1.0));
      const vec3 mcol   = HSV2RGB(vec3(0.1 , 0.95, 0.2));
      const float spe1  = 20.0;
      const float spe2  = 40.0;
      float aa = 2.0/RESOLUTION.y;

      float h = height(p);
      vec3  n = normal(p);

      vec3 ro = vec3(0.0, -10.0, 0.0);
      vec3 pp = vec3(p.x, 0.0, p.y);

      vec3 po = vec3(p.x, h, p.y);
      vec3 rd = normalize(ro - po);

      vec3 ld1 = normalize(lp1 - po);
      vec3 ld2 = normalize(lp2 - po);
      
      float diff1 = max(dot(n, ld1), 0.0);
      float diff2 = max(dot(n, ld2), 0.0);

      vec3  rn    = n;
      vec3  ref   = reflect(rd, rn);
      float ref1  = max(dot(ref, ld1), 0.0);
      float ref2  = max(dot(ref, ld2), 0.0);

      vec3 lpow1 = 0.15*lcol1/DOT2(ld1);
      vec3 lpow2 = 0.25*lcol2/DOT2(ld2);
      vec3 dm = mcol*tanh_approx(-h*5.0+0.125);
      vec3 col = vec3(0.0);
      col += dm*diff1*lpow1;
      col += dm*diff2*lpow2;
      vec3 rm = vec3(1.0)*mix(0.25, 1.0, tanh_approx(-h*1000.0));
      col += rm*pow(ref1, spe1)*lcol1;
      col += rm*pow(ref2, spe2)*lcol2;

      const float top = 10.0;

      col = aces_approx(col);
      col = sRGB(col);

      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = effect(p, q);  
      
      fragColor = vec4(col, 1.0);
    }
    """

    src_b2 = """
    ///////////////////  red waves background - 2

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        // Normalized pixel coordinates (from 0 to 1)
        vec2 uv = 6.0 * fragCoord/iResolution.xy;

        for (int n = 1; n < 20; n++) {
            float i = float(n);
            uv += vec2(1.0 / i * sin(i * uv.y + iTime / 10.0  * i ) + 0.8, 1.0 / i * sin(uv.x + iTime / 10.0 * i) + 1.6);
        }

        vec3 color = vec3(cos(uv.x + uv.y),1,1);
        color *= vec3(.73,.24,.5);

        // Output to screen
        fragColor = vec4(color,1.0);
    } 
    """

    src_vaw = """
    /////////////////// Vista-Esque wallpaper thing

    vec3 palette( float t ) {
        
        vec3 a = vec3(0.667, 0.500, 0.500);
        vec3 b = vec3(0.500, 0.667, 0.500);
        vec3 c = vec3(0.667, 0.666, 0.500);
        vec3 d = vec3(0.200, 0.000, 0.500);
        
        return a + b*cos( 6.28318*(c*t*d) );
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        float wave = sin(iTime*2.);
        
        vec2 uv = fragCoord / iResolution.xy;
        vec3 finalCol = vec3(0);
        
        
        
        for (float i = 0.0; i < 7.0; i++) {
        
            float d = uv.g;
            float w = uv.r;
            
            d = sin(d - 0.3 * 0.1 * (wave/5.+5.)) + sin(uv.r * 2. + iTime/2.)/20. - sin(i)/10. + sin(uv.r * 4.3 + iTime*1.3 * i*0.2)/20.;
            d = abs(d/2.);
            d = 0.003/d /8. *i;
            
            w += sin(uv.g*2. + iTime)/60.;
            w = abs(sin(w*20.*i/4. + iTime*sin(i))/20. + sin(w*10.*i)/17.)*30.;
            w += uv.g*2.4-1.6;
            w /= 3.;
            w = smoothstep(0.4, 0.7, w)/20.;

            vec3 col = palette(uv.r + iTime/3.);

            finalCol += col *= d + w;
        }
        
        fragColor = vec4(finalCol,1.0);
    }
    """

    src_mi = """
    /////////////////// Misty Grid

    float time;

    mat2 rot(float a) {
      float ca=cos(a);
      float sa=sin(a);
      return mat2(ca,sa,-sa,ca);  
    }

    float box(vec3 p, vec3 s) {
      p=abs(p)-s;
      return max(p.x, max(p.y,p.z));
    }

    vec3 fr(vec3 p, float t) {

      //float s = 1.0 - exp(-fract(time*1.0))*0.8;
      float s = 0.7 - smoothstep(0.0,1.0,abs(fract(time*0.1)-0.5)*2.0)*0.3;
      for(int i=0; i<5; ++i) {
        
        float t2=t+float(i);
        p.xy *= rot(t2);
        p.yz *= rot(t2*.7);
        
        float dist = 10.0;
        p=(fract(p/dist-.5)-.5)*dist;
        p=abs(p);
        p-=s;
        
      }
      
      return p;
    }

    float at = 0.;
    float at2 = 0.;
    float at3 = 0.;
    float map(vec3 p) {
      
      
      vec3 bp=p;
      
      p.xy *= rot((p.z*0.023+time*0.1)*0.3);
      p.yz *= rot((p.x*0.087)*0.4);
      
      float t=time*0.5;
      vec3 p2 = fr(p, t * 0.2);
      vec3 p3 = fr(p+vec3(5,0,0), t * 0.23);
      
      float d1 = box(p2, vec3(1,1.3,4));
      float d2 = box(p3, vec3(3,0.7,0.4));
      
      float d = max(abs(d1), abs(d2))-0.2;
      float dist = 1.;
      vec3 p4=(fract(p2/dist-.5)-.5)*dist;
      float d3 = box(p4, vec3(0.4));
      //d = max(d, -d3);
      d = d - d3*0.4;
      
      //d = max(d, length(bp)-15);
      
      
      //float f=p.z + time*4;
      //p.x += sin(f*0.05)*6;
      //p.y += sin(f*0.12)*4;
      //d = max(d, -length(p.xy)+10);
      
      at += 0.13/(0.13+abs(d));
      
      float d5 = box(bp, vec3(4));
      
      float dist2 = 8.;
      vec3 p5=bp;
      p5.z = abs(p5.z)-13.;
      p5.x=(fract(p5.x/dist2-.5)-.5)*dist2;
      float d6 = length(p5.xz)-1.;
      
      at2 += 0.2/(0.15+abs(d5));
      at3 += 0.2/(0.5+abs(d6));
      
      return d;
    }

    void cam(inout vec3 p) {
      
      float t=time*0.1;
      p.yz *= rot(t);
      p.zx *= rot(t*1.2);
    }

    float rnd(vec2 uv) {  
      return fract(dot(sin(uv*752.322+uv.yx*653.842),vec2(254.652)));
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {    
        
      time = iTime * 1.0 + 137.0;
        
      vec2 uv = vec2(fragCoord.x / iResolution.x, fragCoord.y / iResolution.y);
      uv -= 0.5;
      uv /= vec2(iResolution.y / iResolution.x, 1);
      
      float factor = 0.9 + 0.1*rnd(uv);
      //factor = 1;

      vec3 s=vec3(0,0,-15);
      vec3 r=normalize(vec3(-uv, 1));
      
      cam(s);
      cam(r);
      
      vec3 p=s;
      int i=0;
      
      for(i=0; i<80; ++i) {
        float d=abs(map(p));
        d = abs(max(d, -length(p-s)+6.));
        d *= factor;
        if(d<0.001) {
          d = 0.1;
          //break;
        }
        p+=r*d;
      }
      
      vec3 col=vec3(0);
      //col += pow(1-i/101.0,8);
      
      vec3 sky = mix(vec3(1,0.5,0.3), vec3(0.2,1.5,0.7), pow(abs(r.z),8.));
      sky = mix(sky, vec3(0.4,0.5,1.7), pow(abs(r.y),8.));
      
      //col += at*0.002 * sky;
      col += pow(at2*0.008, 1.) * sky;
      col += pow(at3*0.072, 2.) * sky * vec3(0.7,0.3,1.0) * 2.;
      
      col *= 1.2-length(uv);
      
      col = 1.0-exp(-col*15.0);
      col = pow(col, vec3(1.2));
      col *= 1.2;
      //col += 0.2*sky;
      
      //col = vec3(rnd(uv));
      
      fragColor = vec4(col, 1);
    }
    """

    src_fw = """
    /////////////////// Factory Windows
    // fork of https://www.shadertoy.com/view/3dVGDW

    const float PARTITIONS = 10.;

    float dtoa(float d, float amount){
        return 1. / clamp(d*amount, 1., amount);
    }

    vec4 hash42(vec2 p)
    {
        vec4 p4 = fract(vec4(p.xyxy) * vec4(.1031, .1030, .0973, .1099));
        p4 += dot(p4, p4.wzxy+33.33);
        return fract((p4.xxyz+p4.yzzw)*p4.zywx);
    }

    float sdroundedthing(vec2 uv, float size) {
        float ret = length(uv)-size;
        if (uv.y < 0.) {
            ret = min(ret, max(uv.x-size, -uv.x-size));
        }
        return ret;
    }
    // helps movement of ghosts. probably a cheaper way to accomplish this.
    float smoothsquare(float t, float f)
    {
        const float pi = atan(1.)*4.;
        const float delta = .03;// smoothness
        const float A = 1.;// amp
        float y = (A/atan(1./delta))*atan(sin(2.*pi*t*f)/delta);
        return y;
    }

    void mainImage( out vec4 o, in vec2 fragCoord )
    {
        vec2 R = iResolution.xy;
        float t = (iTime+1e2)*.2;
        vec2 uv = fragCoord/iResolution.xy-.5;
        vec2 N = uv;
        uv.x *= R.x / R.y;
        uv.x += .5;
        vec2 uvghost = uv;

        uv.y += t*.3;
        
        // behind the glass...
        float sdghost = 1e6;
        const float ghosts = 9.;
        for (float i = 0.;i < ghosts; ++ i) {
            vec4 h = hash42(vec2(i+2e2));
            vec2 uvg2 = uvghost;
            uvg2.x -= (fract(t*h.x+smoothsquare(t+h.z*2., .5)*.2)-.5)*3.;
            uvg2.y *= sign(h.w-.5);// ceiling
            uvg2.y += h.y*.5;
            sdghost = min(sdghost, sdroundedthing(uvg2, .0));
        }
        
        o = vec4(mix(1.,smoothstep(.0,.4,sdghost), .9));
        //return;

        N *= .98;// oob artifact quickfix

        vec2 cellUL = floor(uv);
        vec2 cellBR = cellUL + 1.5;
        vec2 seed = cellUL;// top-level cell ID

        for(float i = 1.; i <= PARTITIONS; ++ i) {
            vec4 h = hash42(seed+(vec2(cellBR.x, cellUL.y)+10.));
            float dl = abs(uv.x - cellUL.x);// distance to edge of cell, left edge
            dl = min(dl, length(uv.y - cellUL.y));// bottom (inv y)
            dl = min(dl, length(uv.x - cellBR.x));// right
            dl = min(dl, length(uv.y - cellBR.y));// top

            float r = max(fract(N.x-.5), fract(.5-N.x));
            r = max(r, fract(.5-N.y));
            r = max(r, fract(N.y-.5));
            r = 1.-r;
            float col2 = 1.5-dtoa(dl, (h.z+.05)*6000.*pow(r, 1.5));
            vec3 col = h.xyz;
            o.rgb *= col2;
            if (h.w < .1)// sometimes color a window
                o.rgb *= mix(col, vec3(col.r+col.g+col.b)/3.,.8);
            
            h.y = mix(.5, h.y, .2);// favor dividing evenly
            vec2 pt = mix(cellUL, cellBR, h.y);

            if (uv.x < pt.x) {// descend into quadrant
                if (uv.y < pt.y) {
                    cellBR = pt.xy;
                } else {
                    cellUL.y = pt.y;
                    cellBR.x = pt.x;
                }
            } else {
                if (uv.y > pt.y) {
                    cellUL = pt.xy;
                } else {
                    cellUL.x = pt.x;
                    cellBR.y = pt.y;
                }
            }
        }
        
        o = clamp(o,0.,1.);
        o = pow(o,o-o+.7);
        o.a = 1.;
    }
    """

    src_sn = """
    ////////////////// Star Nest
    #define iterations 17
    #define formuparam 0.53

    #define volsteps 20
    #define stepsize 0.1

    #define zoom   0.800
    #define tile   0.850
    #define speed  0.003

    #define brightness 0.0015
    #define darkmatter 0.300
    #define distfading 0.730
    #define saturation 0.850

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        //get coords and direction
        vec2 uv=fragCoord.xy/iResolution.xy-.5;
        uv.y*=iResolution.y/iResolution.x;
        vec3 dir=vec3(uv*zoom,1.);
        float time=iTime*speed+.25;

        //mouse rotation
        float a1=.5+iMouse.x/iResolution.x*0.02;
        float a2=.8+iMouse.y/iResolution.y*0.02;
        mat2 rot1=mat2(cos(a1),sin(a1),-sin(a1),cos(a1));
        mat2 rot2=mat2(cos(a2),sin(a2),-sin(a2),cos(a2));
        dir.xz*=rot1;
        dir.xy*=rot2;
        vec3 from=vec3(1.,.5,0.5);
        from+=vec3(time*2.,time,-2.);
        from.xz*=rot1;
        from.xy*=rot2;

        //volumetric rendering
        float s=0.1,fade=1.;
        vec3 v=vec3(0.);
        for (int r=0; r<volsteps; r++) {
            vec3 p=from+s*dir*.5;
            p = abs(vec3(tile)-mod(p,vec3(tile*2.))); // tiling fold
            float pa,a=pa=0.;
            for (int i=0; i<iterations; i++) { 
                p=abs(p)/dot(p,p)-formuparam; // the magic formula
                a+=abs(length(p)-pa); // absolute sum of average change
                pa=length(p);
            }
            float dm=max(0.,darkmatter-a*a*.001); //dark matter
            a*=a*a; // add contrast
            if (r>6) fade*=1.-dm; // dark matter, don't render near
            //v+=vec3(dm,dm*.5,0.);
            v+=fade;
            v+=vec3(s,s*s,s*s*s*s)*a*brightness*fade; // coloring based on distance
            fade*=distfading; // distance fading
            s+=stepsize;
        }
        v=mix(vec3(length(v)),v,saturation); //color adjust
        fragColor = vec4(v*.01,1.); 
        
    }
    """

    src_nt = """
    ////////////////// Neon Triangle
    // CC0: For the neon style enjoyers
    //  Or is it synthwave style? Don't know!
    //  Anyone been tinkering with this for awhile and now want to get on with other stuff
    //  Hopefully someone enjoys it.

    //#define THAT_CRT_FEELING

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define PI_2        (0.5*PI)
    #define TAU         (2.0*PI)
    #define SCA(a)      vec2(sin(a), cos(a))
    #define ROT(a)      mat2(cos(a), sin(a), -sin(a), cos(a))

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))
    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    vec3 rgb2hsv(vec3 c) {
      const vec4 K = vec4(0.0, -1.0 / 3.0, 2.0 / 3.0, -1.0);
      vec4 p = mix(vec4(c.bg, K.wz), vec4(c.gb, K.xy), step(c.b, c.g));
      vec4 q = mix(vec4(p.xyw, c.r), vec4(c.r, p.yzx), step(p.x, c.r));

      float d = q.x - min(q.w, q.y);
      float e = 1.0e-10;
      return vec3(abs(q.z + (q.w - q.y) / (6.0 * d + e)), d / (q.x + e), q.x);
    }

    const vec3 skyCol       = HSV2RGB(vec3(0.58, 0.86, 1.0));
    const vec3 speCol1      = HSV2RGB(vec3(0.60, 0.25, 1.0));
    const vec3 speCol2      = HSV2RGB(vec3(0.55, 0.25, 1.0));
    const vec3 diffCol1     = HSV2RGB(vec3(0.60, 0.90, 1.0));
    const vec3 diffCol2     = HSV2RGB(vec3(0.55, 0.90, 1.0));
    const vec3 sunCol1      = HSV2RGB(vec3(0.60, 0.50, 0.5));
    const vec3 sunDir2      = normalize(vec3(0., 0.82, 1.0));
    const vec3 sunDir       = normalize(vec3(0.0, 0.05, 1.0));
    const vec3 sunCol       = HSV2RGB(vec3(0.58, 0.86, 0.0005));
    const float mountainPos = -20.0;

    // License: MIT, author: Pascal Gilcher, found: https://www.shadertoy.com/view/flSXRV
    float atan_approx(float y, float x) {
      float cosatan2 = x / (abs(x) + abs(y));
      float t = PI_2 - cosatan2 * PI_2;
      return y < 0.0 ? -t : t;
    }

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
      //  Found this somewhere on the interwebs
      //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    vec3 toSpherical(vec3 p) {
      float r   = length(p);
      float t   = acos(p.z/r);
      float ph  = atan_approx(p.y, p.x);
      return vec3(r, t, ph);
    }

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(vec3 t) {
      return mix(1.055*pow(t, vec3(1./2.4)) - 0.055, 12.92*t, step(t, vec3(0.0031308)));
    }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: MIT OR CC-BY-NC-4.0, author: mercury, found: https://mercury.sexy/hg_sdf/
    float mod1(inout float p, float size) {
      float halfsize = size*0.5;
      float c = floor((p + halfsize)/size);
      p = mod(p + halfsize, size) - halfsize;
      return c;
    }

    // License: MIT OR CC-BY-NC-4.0, author: mercury, found: https://mercury.sexy/hg_sdf/
    vec2 mod2(inout vec2 p, vec2 size) {
      vec2 c = floor((p + size*0.5)/size);
      p = mod(p + size*0.5,size) - size*0.5;
      return c;
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/www/articles/intersectors/intersectors.htm
    float rayPlane(vec3 ro, vec3 rd, vec4 p) {
      return -(dot(ro,p.xyz)+p.w)/dot(rd,p.xyz);
    }


    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/www/articles/distfunctions2d/distfunctions2d.htm
    float equilateralTriangle(vec2 p) {
      const float k = sqrt(3.0);
      p.x = abs(p.x) - 1.0;
      p.y = p.y + 1.0/k;
      if( p.x+k*p.y>0.0 ) p = vec2(p.x-k*p.y,-k*p.x-p.y)/2.0;
      p.x -= clamp( p.x, -2.0, 0.0 );
      return -length(p)*sign(p.y);
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/www/articles/distfunctions2d/distfunctions2d.htm
    float box(vec2 p, vec2 b) {
      vec2 d = abs(p)-b;
      return length(max(d,0.0)) + min(max(d.x,d.y),0.0);
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/www/articles/distfunctions2d/distfunctions2d.htm
    float segment(vec2 p, vec2 a, vec2 b) {
      vec2 pa = p-a, ba = b-a;
      float h = clamp( dot(pa,ba)/dot(ba,ba), 0.0, 1.0 );
      return length(pa - ba*h);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float hash(vec2 co) {
      return fract(sin(dot(co.xy ,vec2(12.9898,58.233))) * 13758.5453);
    }

    // License: MIT, author: Inigo Quilez, found: https://www.shadertoy.com/view/XslGRr
    float vnoise(vec2 p) {
      vec2 i = floor(p);
      vec2 f = fract(p);
        
      vec2 u = f*f*(3.0-2.0*f);

      float a = hash(i + vec2(0.0,0.0));
      float b = hash(i + vec2(1.0,0.0));
      float c = hash(i + vec2(0.0,1.0));
      float d = hash(i + vec2(1.0,1.0));
      
      float m0 = mix(a, b, u.x);
      float m1 = mix(c, d, u.x);
      float m2 = mix(m0, m1, u.y);
      
      return m2;
    }

    // License: MIT, author: Inigo Quilez, found: https://www.iquilezles.org/www/articles/spherefunctions/spherefunctions.htm
    vec2 raySphere(vec3 ro, vec3 rd, vec4 dim) {
      vec3 ce = dim.xyz;
      float ra = dim.w;
      vec3 oc = ro - ce;
      float b = dot( oc, rd );
      float c = dot( oc, oc ) - ra*ra;
      float h = b*b - c;
      if( h<0.0 ) return vec2(-1.0); // no intersection
      h = sqrt( h );
      return vec2( -b-h, -b+h );
    }

    vec3 skyRender(vec3 ro, vec3 rd) {
      vec3 col = vec3(0.0);
      col += 0.025*skyCol;
      col += skyCol*0.0033/pow((1.001+((dot(sunDir2, rd)))), 2.0);

      float tp0  = rayPlane(ro, rd, vec4(vec3(0.0, 1.0, 0.0), 4.0));
      float tp1  = rayPlane(ro, rd, vec4(vec3(0.0, -1.0, 0.0), 6.0));
      float tp = tp1;
      tp = max(tp0,tp1);


      if (tp1 > 0.0) {
        vec3 pos  = ro + tp1*rd;
        vec2 pp = pos.xz;
        float db = box(pp, vec2(5.0, 9.0))-3.0;
        
        col += vec3(4.0)*skyCol*rd.y*rd.y*smoothstep(0.25, 0.0, db);
        col += vec3(0.8)*skyCol*exp(-0.5*max(db, 0.0));
        col += 0.25*sqrt(skyCol)*max(-db, 0.0);
      }

      if (tp0 > 0.0) {
        vec3 pos  = ro + tp0*rd;
        vec2 pp = pos.xz;
        float ds = length(pp) - 0.5;
        
        col += (0.25)*skyCol*exp(-.5*max(ds, 0.0));
      }

      return clamp(col, 0.0, 10.0);
    }

    vec4 sphere(vec3 ro, vec3 rd, vec4 sdim) {
      vec2 si = raySphere(ro, rd, sdim);
      
      vec3 nsp = ro + rd*si.x;

      const vec3 lightPos1   = vec3(0.0, 10.0, 10.0);
      const vec3 lightPos2   = vec3(0.0, -80.0, 10.0);
      
      vec3 nld1   = normalize(lightPos1-nsp); 
      vec3 nld2   = normalize(lightPos2-nsp); 
      
      vec3 nnor   = normalize(nsp - sdim.xyz);

      vec3 nref   = reflect(rd, nnor);

      const float sf = 4.0;
      float ndif1 = max(dot(nld1, nnor), 0.0);
      ndif1       *= ndif1;
      vec3 nspe1  = pow(speCol1*max(dot(nld1, nref), 0.0), sf*vec3(1.0, 0.8, 0.5));

      float ndif2 = max(dot(nld2, nnor), 0.0);
      ndif2       *= ndif2;
      vec3 nspe2  = pow(speCol2*max(dot(nld2, nref), 0.0), sf*vec3(0.9, 0.5, 0.5));

      vec3 nsky   = skyRender(nsp, nref);
      float nfre  = 1.0+dot(rd, nnor);
      nfre        *= nfre;

      vec3 scol = vec3(0.0); 
      scol += nsky*mix(vec3(0.25), vec3(0.5, 0.5, 1.0), nfre);
      scol += diffCol1*ndif1;
      scol += diffCol2*ndif2;
      scol += nspe1;
      scol += nspe2;
      
      float t = tanh_approx(2.0*(si.y-si.x)/sdim.w);
      
      return vec4(scol, t);
    }

    vec3 sphereRender(vec3 ro, vec3 rd) {
      vec3 skyCol = skyRender(ro, rd);
      vec3 col = skyCol;
      const vec4 sdim0 = vec4(vec3(0.0), 2.0);
      vec4 scol0 = sphere(ro, rd, sdim0);
      col = mix(col, scol0.xyz, scol0.w);
      return col;
    }

    vec3 sphereEffect(vec2 p) {
      const float fov = tan(TAU/6.0);
      const vec3 ro = 1.0*vec3(0.0, 2.0, 5.0);
      const vec3 la = vec3(0.0, 0.0, 0.0);
      const vec3 up = vec3(0.0, 1.0, 0.0);

      vec3 ww = normalize(la - ro);
      vec3 uu = normalize(cross(up, ww));
      vec3 vv = cross(ww,uu);
      vec3 rd = normalize(-p.x*uu + p.y*vv + fov*ww);

      vec3 col = sphereRender(ro, rd);
      
      return col;
    }

    vec3 cityOfKali(vec2 p) {
      vec2 c = -vec2(0.5, 0.5)*1.12;

      float s = 2.0;
      vec2 kp = p/s;
     
      const float a = PI/4.0;
      const vec2 n = vec2(cos(a), sin(a));

      float ot2 = 1E6;
      float ot3 = 1E6;
      float n2 = 0.0;
      float n3 = 0.0;

      const float mx = 12.0;
      for (float i = 0.0; i < mx; ++i) {
        float m = (dot(kp, kp));
        s *= m;
        kp = abs(kp)/m + c;
        float d2 = (abs(dot(kp,n)))*s;
        if (d2 < ot2) {
          n2 = i;
          ot2 = d2;
        }
        float d3 = (dot(kp, kp));
        if (d3 < ot3) {
          n3 = i;
          ot3 = d3;
        }
      }
      vec3 col = vec3(0.0);
      n2 /= mx;
      n3 /= mx;
      col += 0.25*(hsv2rgb(vec3(0.8-0.2*n2*n2, 0.90, 0.025))/(sqrt(ot2)+0.0025));
      col += hsv2rgb(vec3(0.55+0.8*n3, 0.85, 0.00000025))/(ot3*ot3+0.000000025);
      return col;
    }

    vec3 outerSkyRender(vec3 ro, vec3 rd) {
      vec3 center = ro+vec3(-100.0, 40.0, 100.0);
      vec4 sdim = vec4(center, 50);
      vec2 pi = raySphere(ro, rd, sdim);
      const vec3 pn = normalize(vec3(0., 1.0, -0.8));
      vec4 pdim = vec4(pn, -dot(pn, center)); 
      float ri = rayPlane(ro, rd, pdim);

      vec3 col = vec3(0.0);
      
      col += sunCol/pow((1.001-((dot(sunDir, rd)))), 2.0);

      if (pi.x != -1.0) {
        vec3 pp = ro + rd*pi.x;
        vec3 psp= pp-sdim.xyz;
        vec3 pn = normalize(pp-sdim.xyz);
        psp = psp.zxy;
        psp.yz *= ROT(-0.5);
        psp.xy *= ROT(0.025*TIME);
        vec3 pss= toSpherical(psp);
        vec3 pcol = vec3(0.0);
        float dif = max(dot(pn, sunDir), 0.0);
        vec3 sc = 2000.0*sunCol;
        pcol += sc*dif;
        pcol += (cityOfKali(pss.yz))*smoothstep(0.125, 0.0, dif);
        pcol += pow(max(dot(reflect(rd, pn), sunDir), 0.0), 9.0)*sc;
        col = mix(col, pcol, tanh_approx(0.125*(pi.y-pi.x)));
        
      }

      vec3 gcol = vec3(0.0);

      vec3 rp = ro + rd*ri;
      float rl = length(rp-center);
      float rb = 1.55*sdim.w;
      float re = 2.45*sdim.w;
      float rw = 0.1*sdim.w;
      vec3 rcol = hsv2rgb(vec3(clamp((0.005*(rl+32.0)), 0.6, 0.8), 0.9, 1.0));
      gcol = rcol*0.025;
      if (ri > 0.0 && (pi.x == -1.0 || ri < pi.x)) {
        float mrl = rl;
        float nrl = mod1(mrl, rw);
        float rfre = 1.0+dot(rd, pn);
        vec3 rrcol = (rcol/max(abs(mrl), 0.1+smoothstep(0.7, 1.0, rfre))); 
        rrcol *= smoothstep(1.0, 0.3, rfre);
        rrcol *= smoothstep(re, re-0.5*rw, rl);
        rrcol *= smoothstep(rb-0.5*rw, rb, rl);
        col += rrcol;;
      }

      col += gcol/max(abs(rd.y), 0.0033);

    return col;
    }

    vec3 triRender(vec3 col, vec3 ro, vec3 rd, inout float maxt) {
      const vec3 tpn = normalize(vec3(0.0, 0.0, 1.0));
      const vec4 tpdim = vec4(tpn, -2.0);
      float tpd = rayPlane(ro, rd, tpdim);

      if (tpd < 0.0 || tpd > maxt) {
        return col;
      }

      vec3 pp = ro+rd*tpd;
      vec2 p = pp.xy;
      p *= 0.5;

      const float off = 1.2-0.02;
      vec2 op = p; 
      p.y -= off;
      const vec2 n = SCA(-PI/3.0);
      vec2 gp = p;
      float hoff = 0.15*dot(n, p);
      vec3 gcol = hsv2rgb(vec3(clamp(0.7+hoff, 0.6, 0.8), 0.90, 0.02));
      vec2 pt = p;
      pt.y = -pt.y;
      const float zt = 1.0;
      float dt = equilateralTriangle(pt/zt)*zt;
    //  col += 2.0*gcol;
      col = dt < 0.0 ? sphereEffect(1.5*(p)) : col;
      col += (gcol/max(abs(dt), 0.001))*smoothstep(0.25, 0.0, dt);
      if (dt < 0.0) {
        maxt = tpd;
      }
      return col;  
    }

    float heightFactor(vec2 p) {
      return 4.0*smoothstep(7.0, 0.5, abs(p.x))+.5;
    }

    float hifbm(vec2 p) {
      p *= 0.25;
      float hf = heightFactor(p);
      const float aa = 0.5;
      const float pp = 2.0-0.;

      float sum = 0.0;
      float a   = 1.0;
      
      for (int i = 0; i < 5; ++i) {
        sum += a*vnoise(p);
        a *= aa;
        p *= pp;
      }
      
      return hf*sum;
    }

    float hiheight(vec2 p) {
      return hifbm(p);
    }

    float lofbm(vec2 p) {
      p *= 0.25;
      float hf = heightFactor(p);
      const float aa = 0.5;
      const float pp = 2.0-0.;

      float sum = 0.0;
      float a   = 1.0;
      
      for (int i = 0; i < 3; ++i) {
        sum += a*vnoise(p);
        a *= aa;
        p *= pp;
      }
      
      return hf*sum;
    }

    float loheight(vec2 p) {
      return lofbm(p)-0.5;
    }

    vec3 mountainRender(vec3 col, vec3 ro, vec3 rd, bool flip, inout float maxt) {
      const vec3 tpn = normalize(vec3(0.0, 0.0, 1.0));
      const vec4 tpdim = vec4(tpn, mountainPos);
      float tpd = rayPlane(ro, rd, tpdim);

      if (tpd < 0.0 || tpd > maxt) {
        return col;
      }

      vec3 pp = ro+rd*tpd;
      vec2 p = pp.xy;
      const float cw = 1.0-0.25;
      float hz = 0.0*TIME+1.0;
      float lo = loheight(vec2(p.x, hz));
      vec2 cp = p;
      float cn = mod1(cp.x, cw);

      const float reps = 1.0;

      float d = 1E3;

      for (float i = -reps; i <= reps; ++i) {
        float x0 = (cn -0.5 + (i))*cw;
        float x1 = (cn -0.5 + (i + 1.0))*cw;
      
        float y0 = hiheight(vec2(x0, hz));
        float y1 = hiheight(vec2(x1, hz));
        
        float dd = segment(cp, vec2(-cw*0.5 + cw * float(i), y0), vec2(cw*0.5 + cw * float(i), y1));
        
        d = min(d, dd);
      }

      vec3 rcol = hsv2rgb(vec3(clamp(0.7+(0.5*(rd.x)), 0.6, 0.8), 0.95, 0.125));

      float sd = 1.0001-((dot(sunDir, rd)));

      vec3 mcol = col;
      float aa = fwidth(p.y);
      if ((dFdy(d) < 0.0) == !flip) {
        mcol *= mix(0.0, 1.0, smoothstep(aa, -aa, d-aa));
        mcol += HSV2RGB(vec3(0.55, 0.85, 0.8))*smoothstep(0.0, 5.0, lo-p.y);
        col = mcol;
        maxt = tpd;
      }
      col += 3.*rcol/(abs(d)+0.005+800.*sd*sd*sd*sd);
      col += HSV2RGB(vec3(0.55, 0.96, 0.075))/(abs(p.y)+0.05);

      return col;  
    }

    vec3 groundRender(vec3 col, vec3 ro, vec3 rd, inout float maxt) {
      const vec3 gpn = normalize(vec3(0.0, 1.0, 0.0));
      const vec4 gpdim = vec4(gpn, 0.0);
      float gpd = rayPlane(ro, rd, gpdim);

      if (gpd < 0.0) {
        return col;
      }

      maxt = gpd;

      vec3 gp     = ro + rd*gpd;
      float gpfre = 1.0 + dot(rd, gpn);
      gpfre *= gpfre;
      gpfre *= gpfre;
      gpfre *= gpfre;
      
      vec3 grr = reflect(rd, gpn);

      vec2 ggp    = gp.xz;
      ggp.y += TIME;
      float dfy   = dFdy(ggp.y);
      float gcf = sin(ggp.x)*sin(ggp.y);
      vec2 ggn    = mod2(ggp, vec2(1.0));
      float ggd   = min(abs(ggp.x), abs(ggp.y));

      vec3 gcol = hsv2rgb(vec3(0.7+0.1*gcf, 0.90, 0.02));

      float rmaxt = 1E6;
      vec3 rcol = outerSkyRender(gp, grr);
      rcol = mountainRender(rcol, gp, grr, true, rmaxt);
      rcol = triRender(rcol, gp, grr, rmaxt);

      col = gcol/max(ggd, 0.0+0.25*dfy)*exp(-0.25*gpd);
      rcol += HSV2RGB(vec3(0.65, 0.85, 1.0))*gpfre;
      rcol = 4.0*tanh(rcol*0.25);
      col += rcol*gpfre;

      return col;
    }

    vec3 render(vec3 ro, vec3 rd) {
      float maxt = 1E6;  

      vec3 col = outerSkyRender(ro, rd);
      col = groundRender(col, ro, rd, maxt);
      col = mountainRender(col, ro, rd, false, maxt);
      col = triRender(col, ro, rd, maxt);

      return col;
    }

    vec3 effect(vec2 p, vec2 pp) {
      const float fov = tan(TAU/6.0);
      const vec3 ro = 1.0*vec3(0.0, 1.0, -4.);
      const vec3 la = vec3(0.0, 1.0, 0.0);
      const vec3 up = vec3(0.0, 1.0, 0.0);

      vec3 ww = normalize(la - ro);
      vec3 uu = normalize(cross(up, ww));
      vec3 vv = cross(ww,uu);
      vec3 rd = normalize(-p.x*uu + p.y*vv + fov*ww);

      float aa = 2.0/RESOLUTION.y;

      vec3 col = render(ro, rd);
    #if defined(THAT_CRT_FEELING)  
      col *= smoothstep(1.5, 0.5, length(pp));
      col *= 1.25*mix(vec3(0.5), vec3(1.0),smoothstep(-0.9, 0.9, sin(0.25*TAU*p.y/aa+TAU*vec3(0.0, 1., 2.0)/3.0)));
    #endif  
      col -= 0.05*vec3(.00, 1.0, 2.0).zyx;
      col = aces_approx(col); 
      col = sRGB(col);
      return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      vec2 q = fragCoord/RESOLUTION.xy;

      vec2 p = -1. + 2. * q;
      vec2 pp = p;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = effect(p, pp);

      fragColor = vec4(col, 1.0);
    }
    """

    src_ff = """
    ///////////////////// 
    // I started working a bit on the colors of Remix 2, ended up with something like this. :)
    // Remix 2 here: https://www.shadertoy.com/view/MtcGD7
    // Remix 1 here: https://www.shadertoy.com/view/llc3DM
    // Original here: https://www.shadertoy.com/view/XsXXRN

    float rand(vec2 n) {
        return fract(sin(cos(dot(n, vec2(12.9898,12.1414)))) * 83758.5453);
    }

    float noise(vec2 n) {
        const vec2 d = vec2(0.0, 1.0);
        vec2 b = floor(n), f = smoothstep(vec2(0.0), vec2(1.0), fract(n));
        return mix(mix(rand(b), rand(b + d.yx), f.x), mix(rand(b + d.xy), rand(b + d.yy), f.x), f.y);
    }

    float fbm(vec2 n) {
        float total = 0.0, amplitude = 1.0;
        for (int i = 0; i <5; i++) {
            total += noise(n) * amplitude;
            n += n*1.7;
            amplitude *= 0.47;
        }
        return total;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {

        const vec3 c1 = vec3(0.5, 0.0, 0.1);
        const vec3 c2 = vec3(0.9, 0.1, 0.0);
        const vec3 c3 = vec3(0.2, 0.1, 0.7);
        const vec3 c4 = vec3(1.0, 0.9, 0.1);
        const vec3 c5 = vec3(0.1);
        const vec3 c6 = vec3(0.9);

        vec2 speed = vec2(0.1, 0.9);
        float shift = 1.327+sin(iTime*2.0)/2.4;
        float alpha = 1.0;

        float dist = 3.5-sin(iTime*0.4)/1.89;

        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 p = fragCoord.xy * dist / iResolution.xx;
        p += sin(p.yx*4.0+vec2(.2,-.3)*iTime)*0.04;
        p += sin(p.yx*8.0+vec2(.6,+.1)*iTime)*0.01;

        p.x -= iTime/1.1;
        float q = fbm(p - iTime * 0.3+1.0*sin(iTime+0.5)/2.0);
        float qb = fbm(p - iTime * 0.4+0.1*cos(iTime)/2.0);
        float q2 = fbm(p - iTime * 0.44 - 5.0*cos(iTime)/2.0) - 6.0;
        float q3 = fbm(p - iTime * 0.9 - 10.0*cos(iTime)/15.0)-4.0;
        float q4 = fbm(p - iTime * 1.4 - 20.0*sin(iTime)/14.0)+2.0;
        q = (q + qb - .4 * q2 -2.0*q3  + .6*q4)/3.8;
        vec2 r = vec2(fbm(p + q /2.0 + iTime * speed.x - p.x - p.y), fbm(p + q - iTime * speed.y));
        vec3 c = mix(c1, c2, fbm(p + r)) + mix(c3, c4, r.x) - mix(c5, c6, r.y);
        vec3 color = vec3(1.0/(pow(c+1.61,vec3(4.0))) * cos(shift * fragCoord.y / iResolution.y));

        color=vec3(1.0,.2,.05)/(pow((r.y+r.y)* max(.0,p.y)+0.1, 4.0));;
        color += (texture(iChannel0,uv*0.6+vec2(.5,.1)).xyz*0.01*pow((r.y+r.y)*.65,5.0)+0.055)*mix( vec3(.9,.4,.3),vec3(.7,.5,.2), uv.y);
        color = color/(1.0+max(vec3(0),color));
        fragColor = vec4(color.x, color.y, color.z, alpha);
    }
    """

    src_ub = """
    ////////////////// Colorful underwater bubbles II
    // CCO: Colorful underwater bubbles II
    //  Recoloring of earlier shader + spherical shading

    #define TIME        iTime
    #define RESOLUTION  iResolution
    #define PI          3.141592654
    #define TAU         (2.0*PI)
    const float MaxIter = 12.0;

    // License: Unknown, author: Unknown, found: don't remember
    float hash(float co) {
      return fract(sin(co*12.9898) * 13758.5453);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float hash(vec2 co) {
      return fract(sin(dot(co.xy ,vec2(12.9898,58.233))) * 13758.5453);
    }

    // License: MIT OR CC-BY-NC-4.0, author: mercury, found: https://mercury.sexy/hg_sdf/
    vec2 mod2(inout vec2 p, vec2 size) {
      vec2 c = floor((p + size*0.5)/size);
      p = mod(p + size*0.5,size) - size*0.5;
      return c;
    }

    vec4 plane(vec2 p, float i, float zf, float z, vec3 bgcol) {
      float sz = 0.5*zf;
      vec2 cp = p;
      vec2 cn = mod2(cp, vec2(2.0*sz, sz));
      float h0 = hash(cn+i+123.4);
      float h1 = fract(4483.0*h0);
      float h2 = fract(8677.0*h0);
      float h3 = fract(9677.0*h0);
      float h4 = fract(7877.0*h0);
      float h5 = fract(9967.0*h0);
      if (h4 < 0.5) {
        return vec4(0.0);
      }
      float fi = exp(-0.25*max(z-2.0, 0.0));
      float aa = mix(0.0125, 2.0/RESOLUTION.y, fi); 
      float r  = sz*mix(0.1, 0.475, h0*h0);
      float amp = mix(0.5, 0.5, h3)*r;
      cp.x -= amp*sin(mix(3.0, 0.25, h0)*TIME+TAU*h2);
      cp.x += 0.95*(sz-r-amp)*sign(h3-0.5)*h3;
      cp.y += 0.475*(sz-2.0*r)*sign(h5-0.5)*h5;
      float d = length(cp)-r;
      if (d > aa) {
        return vec4(0.0);
      }
      vec3 ocol = (0.5+0.5*sin(vec3(0.0, 1.0, 2.0)+h1*TAU));
      vec3 icol = sqrt(ocol);
      ocol *= 1.5;
      icol *= 2.0;
      const vec3 lightDir = normalize(vec3(1.0, 1.5, 2.0));
      float z2 = (r*r-dot(cp, cp));
      vec3 col = ocol;
      float t = smoothstep(aa, -aa, d);
      if (z2 > 0.0) {
        float z = sqrt(z2);
        t *= mix(1.0, 0.8, z/r);
        vec3 pp = vec3(cp, z);
        vec3 nn = normalize(pp);
        float dd= max(dot(lightDir, nn), 0.0);

        col = mix(ocol, icol, dd*dd*dd);
      }
      col *= mix(0.8, 1.0, h0);
      col = mix(bgcol, col, fi);
      return vec4(col, t);
    }

    // License: Unknown, author: Claude Brezinski, found: https://mathr.co.uk/blog/2017-09-06_approximating_hyperbolic_tangent.html
    float tanh_approx(float x) {
      //  Found this somewhere on the interwebs
      //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    vec3 effect(vec2 p, vec2 pp) {
      const vec3 bgcol0 = vec3(0.1, 0.0, 1.0)*0.1;
      const vec3 bgcol1 = vec3(0.0, 0.4, 1.0)*0.6;
      vec3 bgcol = mix(bgcol1, bgcol0, tanh_approx(1.5*length(p)));
      vec3 col = bgcol;

      for (float i = 0.0; i < MaxIter; ++i) {
        const float Near = 4.0;
        float z = MaxIter - i;
        float zf = Near/(Near + MaxIter - i);
        vec2 sp = p;
        float h = hash(i+1234.5); 
        sp.y += -mix(0.2, 0.3, h*h)*TIME*zf;
        sp += h;
        vec4 pcol = plane(sp, i, zf, z, bgcol);
        col = mix(col, pcol.xyz, pcol.w);
      }
      col *= smoothstep(1.5, 0.5, length(pp));
      col = clamp(col, 0.0, 1.0);
      col = sqrt(col);
      return col;
    }

    void mainImage(out vec4 fragColor, in vec2 fragCoord) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      vec2 pp = p;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      vec3 col = effect(p, pp);
      fragColor = vec4(col, 1.0);
    }
    """

    src_uw = """
    ////////////////// The Universe Within

    #define S(a, b, t) smoothstep(a, b, t)
    #define NUM_LAYERS 4.

    //#define SIMPLE

    float N21(vec2 p) {
        vec3 a = fract(vec3(p.xyx) * vec3(213.897, 653.453, 253.098));
        a += dot(a, a.yzx + 79.76);
        return fract((a.x + a.y) * a.z);
    }

    vec2 GetPos(vec2 id, vec2 offs, float t) {
        float n = N21(id+offs);
        float n1 = fract(n*10.);
        float n2 = fract(n*100.);
        float a = t+n;
        return offs + vec2(sin(a*n1), cos(a*n2))*.4;
    }

    float GetT(vec2 ro, vec2 rd, vec2 p) {
        return dot(p-ro, rd); 
    }

    float LineDist(vec3 a, vec3 b, vec3 p) {
        return length(cross(b-a, p-a))/length(p-a);
    }

    float df_line( in vec2 a, in vec2 b, in vec2 p)
    {
        vec2 pa = p - a, ba = b - a;
        float h = clamp(dot(pa,ba) / dot(ba,ba), 0., 1.);   
        return length(pa - ba * h);
    }

    float line(vec2 a, vec2 b, vec2 uv) {
        float r1 = .04;
        float r2 = .01;

        float d = df_line(a, b, uv);
        float d2 = length(a-b);
        float fade = S(1.5, .5, d2);

        fade += S(.05, .02, abs(d2-.75));
        return S(r1, r2, d)*fade;
    }

    float NetLayer(vec2 st, float n, float t) {
        vec2 id = floor(st)+n;

        st = fract(st)-.5;

        vec2 p[9];
        int i=0;
        for(float y=-1.; y<=1.; y++) {
            for(float x=-1.; x<=1.; x++) {
                p[i++] = GetPos(id, vec2(x,y), t);
            }
        }

        float m = 0.;
        float sparkle = 0.;

        for(int i=0; i<9; i++) {
            m += line(p[4], p[i], st);

            float d = length(st-p[i]);

            float s = (.005/(d*d));
            s *= S(1., .7, d);
            float pulse = sin((fract(p[i].x)+fract(p[i].y)+t)*5.)*.4+.6;
            pulse = pow(pulse, 20.);

            s *= pulse;
            sparkle += s;
        }

        m += line(p[1], p[3], st);
        m += line(p[1], p[5], st);
        m += line(p[7], p[5], st);
        m += line(p[7], p[3], st);

        float sPhase = (sin(t+n)+sin(t*.1))*.25+.5;
        sPhase += pow(sin(t*.1)*.5+.5, 50.)*5.;
        m += sparkle*sPhase;//(*.5+.5);

        return m;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord-iResolution.xy*.5)/iResolution.y;
        vec2 M = iMouse.xy/iResolution.xy-.5;

        float t = iTime*.1;

        float s = sin(t);
        float c = cos(t);
        mat2 rot = mat2(c, -s, s, c);
        vec2 st = uv*rot;  
        M *= rot*2.;

        float m = 0.;
        for(float i=0.; i<1.; i+=1./NUM_LAYERS) {
            float z = fract(t+i);
            float size = mix(15., 1., z);
            float fade = S(0., .6, z)*S(1., .8, z);

            m += fade * NetLayer(st*size-M*z, i, iTime);
        }

        float fft  = texelFetch( iChannel0, ivec2(.7,0), 0 ).x;
        float glow = -uv.y*fft*2.;

        vec3 baseCol = vec3(s, cos(t*.4), -sin(t*.24))*.4+.6;
        vec3 col = baseCol*m;
        col += baseCol*glow;

        #ifdef SIMPLE
        uv *= 10.;
        col = vec3(1)*NetLayer(uv, 0., iTime);
        uv = fract(uv);
        //if(uv.x>.98 || uv.y>.98) col += 1.;
        #else
        col *= 1.-dot(uv,uv);
        t = mod(iTime, 230.);
        col *= S(0., 20., t)*S(224., 200., t);
        #endif

        fragColor = vec4(col,1);
    }
    """

    src_fg = """
    ////////////////// Fractal Galaxy
    //CBS
    //Parallax scrolling fractal galaxy.
    //Inspired by JoshP's Simplicity shader: https://www.shadertoy.com/view/lslGWr
    // http://www.fractalforums.com/new-theories-and-research/very-simple-formula-for-fractal-patterns/

    float field(in vec3 p,float s) {
        float strength = 7. + .03 * log(1.e-6 + fract(sin(iTime) * 4373.11));
        float accum = s/4.;
        float prev = 0.;
        float tw = 0.;
        for (int i = 0; i < 26; ++i) {
            float mag = dot(p, p);
            p = abs(p) / mag + vec3(-.5, -.4, -1.5);
            float w = exp(-float(i) / 7.);
            accum += w * exp(-strength * pow(abs(mag - prev), 2.2));
            tw += w;
            prev = mag;
        }
        return max(0., 5. * accum / tw - .7);
    }

    // Less iterations for second layer
    float field2(in vec3 p, float s) {
        float strength = 7. + .03 * log(1.e-6 + fract(sin(iTime) * 4373.11));
        float accum = s/4.;
        float prev = 0.;
        float tw = 0.;
        for (int i = 0; i < 18; ++i) {
            float mag = dot(p, p);
            p = abs(p) / mag + vec3(-.5, -.4, -1.5);
            float w = exp(-float(i) / 7.);
            accum += w * exp(-strength * pow(abs(mag - prev), 2.2)); 
            tw += w;
            prev = mag;
        }
        return max(0., 5. * accum / tw - .7);
    }

    vec3 nrand3( vec2 co )
    {
        vec3 a = fract( cos( co.x*8.3e-3 + co.y )*vec3(1.3e5, 4.7e5, 2.9e5) );
        vec3 b = fract( sin( co.x*0.3e-3 + co.y )*vec3(8.1e5, 1.0e5, 0.1e5) );
        vec3 c = mix(a, b, 0.5);
        return c;
    }


    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
        vec2 uv = 2. * fragCoord.xy / iResolution.xy - 1.;
        vec2 uvs = uv * iResolution.xy / max(iResolution.x, iResolution.y);
        vec3 p = vec3(uvs / 4., 0) + vec3(1., -1.3, 0.);
        p += .2 * vec3(sin(iTime / 16.), sin(iTime / 12.),  sin(iTime / 128.));
        
        float freqs[4];
        //Sound
        freqs[0] = texture( iChannel0, vec2( 0.01, 0.25 ) ).x;
        freqs[1] = texture( iChannel0, vec2( 0.07, 0.25 ) ).x;
        freqs[2] = texture( iChannel0, vec2( 0.15, 0.25 ) ).x;
        freqs[3] = texture( iChannel0, vec2( 0.30, 0.25 ) ).x;

        float t = field(p,freqs[2]);
        float v = (1. - exp((abs(uv.x) - 1.) * 6.)) * (1. - exp((abs(uv.y) - 1.) * 6.));

        //Second Layer
        vec3 p2 = vec3(uvs / (4.+sin(iTime*0.11)*0.2+0.2+sin(iTime*0.15)*0.3+0.4), 1.5) + vec3(2., -1.3, -1.);
        p2 += 0.25 * vec3(sin(iTime / 16.), sin(iTime / 12.),  sin(iTime / 128.));
        float t2 = field2(p2,freqs[3]);
        vec4 c2 = mix(.4, 1., v) * vec4(1.3 * t2 * t2 * t2 ,1.8  * t2 * t2 , t2* freqs[0], t2);

        //Let's add some stars
        //Thanks to http://glsl.heroku.com/e#6904.0
        vec2 seed = p.xy * 2.0; 
        seed = floor(seed * iResolution.x);
        vec3 rnd = nrand3( seed );
        vec4 starcolor = vec4(pow(rnd.y,40.0));

        //Second Layer
        vec2 seed2 = p2.xy * 2.0;
        seed2 = floor(seed2 * iResolution.x);
        vec3 rnd2 = nrand3( seed2 );
        starcolor += vec4(pow(rnd2.y,40.0));

        fragColor = mix(freqs[3]-.3, 1., v) * vec4(1.5*freqs[2] * t * t* t , 1.2*freqs[1] * t * t, freqs[3]*t, 1.0)+c2+starcolor;
    }
    """

    src_gs = """
    ///////////////////////// glowing stars
    // Originally from: https://www.shadertoy.com/view/ttBcRV
    // License CC0: Flying through glowing stars
    //  The result of playing around trying to improve an old shader

    #define PI              3.141592654
    #define TAU             (2.0*PI)
    #define TIME            iTime
    #define RESOLUTION      iResolution

    #define LESS(a,b,c)     mix(a,b,step(0.,c))
    #define SABS(x,k)       LESS((.5/(k))*(x)*(x)+(k)*.5,abs(x),abs(x)-(k))

    #define MROT(a) mat2(cos(a), sin(a), -sin(a), cos(a))

    vec3 hsv2rgb(vec3 c) {
      const vec4 K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
      vec3 p = abs(fract(c.xxx + K.xyz) * 6.0 - K.www);
      return c.z * mix(K.xxx, clamp(p - K.xxx, 0.0, 1.0), c.y);
    }

    float hash(in vec3 co) {
      return fract(sin(dot(co, vec3(12.9898,58.233, 12.9898+58.233))) * 13758.5453);
    }

    float starn(vec2 p, float r, int n, float m) {
      // From IQ: https://www.shadertoy.com/view/3tSGDy
      // https://iquilezles.org/www/articles/distfunctions2d/distfunctions2d.htm

      // Minor tweak to use SABS over abs to smooth inner corners
      // SABS: https://www.shadertoy.com/view/Ws2SDK

      // next 4 lines can be precomputed for a given shape
      float an = 3.141593/float(n);
      float en = 3.141593/m;  // m is between 2 and n
      vec2  acs = vec2(cos(an),sin(an));
      vec2  ecs = vec2(cos(en),sin(en)); // ecs=vec2(0,1) for regular polygon,

      float bn = mod(atan(p.x,p.y),2.0*an) - an;
      p = length(p)*vec2(cos(bn),SABS(sin(bn), 0.15));
      p -= r*acs;
      p += ecs*clamp( -dot(p,ecs), 0.0, r*acs.y/ecs.y);
      return length(p)*sign(p.x);
    }

    vec4 alphaBlend(vec4 back, vec4 front) {
      vec3 xyz = mix(back.xyz*back.w, front.xyz, front.w);
      float w = mix(back.w, 1.0, front.w);
      return vec4(xyz, w);
    }

    void rot(inout vec2 p, float a) {
      float c = cos(a);
      float s = sin(a);
      p = vec2(c*p.x + s*p.y, -s*p.x + c*p.y);
    }

    vec3 offset(float z) {
      float a = z;
      vec2 p = -0.075*(vec2(cos(a), sin(a*sqrt(2.0))) + vec2(cos(a*sqrt(0.75)), sin(a*sqrt(0.5))));
      return vec3(p, z);
    }

    vec3 doffset(float z) {
      float eps = 0.05;
      return 0.5*(offset(z + eps) - offset(z - eps))/eps;
    }

    vec3 ddoffset(float z) {
      float eps = 0.05;
      return 0.5*(doffset(z + eps) - doffset(z - eps))/eps;
    }

    vec4 planeCol(vec3 ro, vec3 rd, float n, vec3 pp) {
      const float s = 0.5;

      vec2 p = pp.xy;
      float z = pp.z;
      vec2 dpy = dFdy(p);
      float aa = length(dpy);

      p -= (1.0+5.0*(pp.z - ro.z))*offset(z).xy;

      p *= s;
      float r = hash(vec3(floor(p+0.5), n));
      p = fract(p+0.5)-0.5;
      rot(p, ((TAU*r+n)*0.25));
      float d = starn(p, 0.20, 3 + 2*int(3.0*r), 3.0);
      d -= 0.06;
      d/=s;

      float ds = -d+0.03;
      vec3 cols = hsv2rgb(vec3(337.0/360.0+0.1*sin(n*0.3), 0.8, 0.54+0.2*sin(n*0.3)));
      float ts = 1.0 - smoothstep(-aa, 0.0, ds);
      vec4 cs =  vec4(cols, ts*0.93);

      float db = abs(d) - (0.06);
      db = abs(db) - 0.03;
      db = abs(db) - 0.00;
      db = max(db, -d+0.03);
        vec3 colb = vec3(1.0, 0.7, 0.5);
      float tb = exp(-(db)*30.0*(1.0 - 10.0*aa));
      vec4 cb = vec4(1.5*colb, tb);

      vec4 ct = alphaBlend(cs, cb);

      return ct;
    }

    vec3 color(vec3 ww, vec3 uu, vec3 vv, vec3 ro, vec2 p) {
      vec3 rd = normalize(p.x*uu + p.y*vv + (2.0-tanh(length(p)))*ww);

      vec4 col = vec4(vec3(0.0), 1.0);

      const float planeDist = 1.0;
      const int furthest = 6;
      const int fadeFrom = furthest-3;

      float nz = floor(ro.z / planeDist);

      for (int i = furthest; i >= 1; --i) {
        float pz = planeDist*nz + planeDist*float(i);

        float pd = (pz - ro.z)/rd.z;

        if (pd > 0.0) {
          vec3 pp = ro + rd*pd;

          vec4 pcol = planeCol(ro, rd, nz+float(i), pp);
          float fadeIn = 1.0-smoothstep(planeDist*float(fadeFrom), planeDist*float(furthest), pp.z-ro.z);
          pcol.xyz *= sqrt(fadeIn);

          col = alphaBlend(col, pcol);
        }
      }

      return col.xyz*col.w;
    }

    vec3 postProcess(vec3 col, vec2 q)  {
      col=pow(clamp(col,0.0,1.0),vec3(0.75));
      col=col*0.6+0.4*col*col*(3.0-2.0*col);
      col=mix(col, vec3(dot(col, vec3(0.33))), -0.4);
      col*=0.5+0.5*pow(19.0*q.x*q.y*(1.0-q.x)*(1.0-q.y),0.7);
      return col;
    }

    vec3 effect(vec2 p, vec2 q) {
      float tm = TIME*0.65;

      vec3 ro   = offset(tm);
      vec3 dro  = doffset(tm);
      vec3 ddro = ddoffset(tm);

      vec3 ww = normalize(dro);
      vec3 uu = normalize(cross(vec3(0.0,1.0,0.0)+1.5*ddro, ww));
      vec3 vv = normalize(cross(ww, uu));

      vec3 col = color(ww, uu, vv, ro, p);
      col = postProcess(col, q);

      const float fadeIn = 2.0;

      return col*smoothstep(0.0, fadeIn, TIME);
    }

    void mainImage(out vec4 fragColor, vec2 fragCoord) {
      vec2 q = fragCoord/RESOLUTION.xy;
      vec2 p = -1. + 2. * q;
      p.x *= RESOLUTION.x/RESOLUTION.y;

      vec3 col = effect(p, q);

      fragColor = vec4(col, 1.0);
    }
    """

    src_nn = """
    ///////////////////// colored bagel
    // https://www.desmos.com/calculator/hapltffosd
    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (2.*fragCoord.xy - iResolution.xy) / iResolution.y;

        float dist = dot(uv, uv) / 2.0 - 0.25;
        float quadrantDiv = uv.y / (uv.x + 0.001);
        
        float ax_ = quadrantDiv / (0.77 + 0.21*quadrantDiv*quadrantDiv) + sin(iTime)/2.0 - 0.5;
        vec4 a = ax_ + vec4(0, 1.5, 3, 4.5);

        vec4 b = 1.6 * a * (3.14 - a) / (50. - 4.*a*(3.14 - a));

        vec4 b_ = b.yzwx;
        vec4 bg = max(dist - b, b_ - dist);

        float dot_ = dot(clamp(vec4(0.), bg * 720., vec4(72.)), b);

        vec3 rgb = dot_ * (b.rgb - 0.15);

        fragColor = vec4(rgb, 1.);
    }
    """

    src_pp = """
    ///////////////////// Protophore
    /*------------------------------------------------------------------------------
    License CC0 - http://creativecommons.org/publicdomain/zero/1.0/
    To the extent possible under law, the author(s) have dedicated all copyright and
    related and neighboring rights to this software to the public domain worldwide.
    This software is distributed without any warranty.
    --------------------------------------------------------------------------------
    ^This means do anything you want with this code. Because we are programmers, not lawyers.
    -Otavio Good
    */

    // Number of times the fractal repeats
    #define RECURSION_LEVELS 4

    // Animation splits the sphere in different directions
    // This ended up running a significantly slower fps and not looking very different. :(
    //#define SPLIT_ANIM

    float localTime = 0.0;
    float marchCount;

    float PI=3.14159265;

    vec3 saturate(vec3 a) { return clamp(a, 0.0, 1.0); }
    vec2 saturate(vec2 a) { return clamp(a, 0.0, 1.0); }
    float saturate(float a) { return clamp(a, 0.0, 1.0); }

    vec3 RotateX(vec3 v, float rad)
    {
      float cos = cos(rad);
      float sin = sin(rad);
      return vec3(v.x, cos * v.y + sin * v.z, -sin * v.y + cos * v.z);
    }
    vec3 RotateY(vec3 v, float rad)
    {
      float cos = cos(rad);
      float sin = sin(rad);
      return vec3(cos * v.x - sin * v.z, v.y, sin * v.x + cos * v.z);
    }
    vec3 RotateZ(vec3 v, float rad)
    {
      float cos = cos(rad);
      float sin = sin(rad);
      return vec3(cos * v.x + sin * v.y, -sin * v.x + cos * v.y, v.z);
    }

    /*vec3 GetEnvColor(vec3 rayDir, vec3 sunDir)
    {
        vec3 tex = texture(iChannel0, rayDir).xyz;
        tex = tex * tex;    // gamma correct
        return tex;
    }*/

    // This is a procedural environment map with a giant overhead softbox,
    // 4 lights in a horizontal circle, and a bottom-to-top fade.
    vec3 GetEnvColor2(vec3 rayDir, vec3 sunDir)
    {
        // fade bottom to top so it looks like the softbox is casting light on a floor
        // and it's bouncing back
        vec3 final = vec3(1.0) * dot(-rayDir, sunDir) * 0.5 + 0.5;
        final *= 0.125;
        // overhead softbox, stretched to a rectangle
        if ((rayDir.y > abs(rayDir.x)*1.0) && (rayDir.y > abs(rayDir.z*0.25))) final = vec3(2.0)*rayDir.y;
        // fade the softbox at the edges with a rounded rectangle.
        float roundBox = length(max(abs(rayDir.xz/max(0.0,rayDir.y))-vec2(0.9, 4.0),0.0))-0.1;
        final += vec3(0.8)* pow(saturate(1.0 - roundBox*0.5), 6.0);
        // purple lights from side
        final += vec3(8.0,6.0,7.0) * saturate(0.001/(1.0 - abs(rayDir.x)));
        // yellow lights from side
        final += vec3(8.0,7.0,6.0) * saturate(0.001/(1.0 - abs(rayDir.z)));
        return vec3(final);
    }

    /*vec3 GetEnvColorReflection(vec3 rayDir, vec3 sunDir, float ambient)
    {
        vec3 tex = texture(iChannel0, rayDir).xyz;
        tex = tex * tex;
        vec3 texBack = texture(iChannel0, rayDir).xyz;
        vec3 texDark = pow(texBack, vec3(50.0)).zzz;    // fake hdr texture
        texBack += texDark*0.5 * ambient;
        return texBack*texBack*texBack;
    }*/

    vec3 camPos = vec3(0.0), camFacing;
    vec3 camLookat=vec3(0,0.0,0);

    // polynomial smooth min (k = 0.1);
    float smin( float a, float b, float k )
    {
        float h = clamp( 0.5+0.5*(b-a)/k, 0.0, 1.0 );
        return mix( b, a, h ) - k*h*(1.0-h);
    }

    vec2 matMin(vec2 a, vec2 b)
    {
        if (a.x < b.x) return a;
        else return b;
    }

    float spinTime;
    vec3 diagN = normalize(vec3(-1.0));
    float cut = 0.77;
    float inner = 0.333;
    float outness = 1.414;
    float finWidth;
    float teeth;
    float globalTeeth;

    vec2 sphereIter(vec3 p, float radius, float subA)
    {
        finWidth = 0.1;
        teeth = globalTeeth;
        float blender = 0.25;
        vec2 final = vec2(1000000.0, 0.0);
        for (int i = 0; i < RECURSION_LEVELS; i++)
        {
    #ifdef SPLIT_ANIM
            // rotate top and bottom of sphere opposite directions
            p = RotateY(p, spinTime*sign(p.y)*0.05/blender);
    #endif
            // main sphere
            float d = length(p) - radius*outness;
    #ifdef SPLIT_ANIM
            // subtract out disc at the place where rotation happens so we don't have artifacts
            d = max(d, -(max(length(p) - radius*outness + 0.1, abs(p.y) - finWidth*0.25)));
    #endif

            // calc new position at 8 vertices of cube, scaled
            vec3 corners = abs(p) + diagN * radius;
            float lenCorners = length(corners);
            // subtract out main sphere hole, mirrored on all axises
            float subtracter = lenCorners - radius * subA;
            // make mirrored fins that go through all vertices of the cube
            vec3 ap = abs(-p) * 0.7071; // 1/sqrt(2) to keep distance field normalized
            subtracter = max(subtracter, -(abs(ap.x-ap.y) - finWidth));
            subtracter = max(subtracter, -(abs(ap.y-ap.z) - finWidth));
            subtracter = max(subtracter, -(abs(ap.z-ap.x) - finWidth));
            // subtract sphere from fins so they don't intersect the inner spheres.
            // also animate them so they are like teeth
            subtracter = min(subtracter, lenCorners - radius * subA + teeth);
            // smoothly subtract out that whole complex shape
            d = -smin(-d, subtracter, blender);
            //vec2 sphereDist = sphereB(abs(p) + diagN * radius, radius * inner, cut);  // recurse
            // do a material-min with the last iteration
            final = matMin(final, vec2(d, float(i)));

    #ifndef SPLIT_ANIM
            corners = RotateY(corners, spinTime*0.25/blender);
    #endif
            // Simple rotate 90 degrees on X axis to keep things fresh
            p = vec3(corners.x, corners.z, -corners.y);
            // Scale things for the next iteration / recursion-like-thing
            radius *= inner;
            teeth *= inner;
            finWidth *= inner;
            blender *= inner;
        }
        // Bring in the final smallest-sized sphere
        float d = length(p) - radius*outness;
        final = matMin(final, vec2(d, 6.0));
        return final;
    }

    vec2 DistanceToObject(vec3 p)
    {
        vec2 distMat = sphereIter(p, 5.2 / outness, cut);
        return distMat;
    }

    // dirVec MUST BE NORMALIZED FIRST!!!!
    float SphereIntersect(vec3 pos, vec3 dirVecPLZNormalizeMeFirst, vec3 spherePos, float rad)
    {
        vec3 radialVec = pos - spherePos;
        float b = dot(radialVec, dirVecPLZNormalizeMeFirst);
        float c = dot(radialVec, radialVec) - rad * rad;
        float h = b * b - c;
        if (h < 0.0) return -1.0;
        return -b - sqrt(h);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        localTime = iTime - 0.0;
        // ---------------- First, set up the camera rays for ray marching ----------------
        vec2 uv = fragCoord.xy/iResolution.xy * 2.0 - 1.0;
        float zoom = 1.7;
        uv /= zoom;

        // Camera up vector.
        vec3 camUp=vec3(0,1,0);

        // Camera lookat.
        camLookat=vec3(0,0.0,0);

        // debugging camera
        float mx=iMouse.x/iResolution.x*PI*2.0-0.7 + localTime*3.1415 * 0.0625*0.666;
        float my=-iMouse.y/iResolution.y*10.0 - sin(localTime * 0.31)*0.5;//*PI/2.01;
        camPos += vec3(cos(my)*cos(mx),sin(my),cos(my)*sin(mx))*(12.2);

        // Camera setup.
        vec3 camVec=normalize(camLookat - camPos);
        vec3 sideNorm=normalize(cross(camUp, camVec));
        vec3 upNorm=cross(camVec, sideNorm);
        vec3 worldFacing=(camPos + camVec);
        vec3 worldPix = worldFacing + uv.x * sideNorm * (iResolution.x/iResolution.y) + uv.y * upNorm;
        vec3 rayVec = normalize(worldPix - camPos);

        // ----------------------------------- Animate ------------------------------------
        localTime = iTime*0.5;
        // This is a wave function like a triangle wave, but with flat tops and bottoms.
        // period is 1.0
        float rampStep = min(3.0,max(1.0, abs((fract(localTime)-0.5)*1.0)*8.0))*0.5-0.5;
        rampStep = smoothstep(0.0, 1.0, rampStep);
        // lopsided triangle wave - goes up for 3 time units, down for 1.
        float step31 = (max(0.0, (fract(localTime+0.125)-0.25)) - min(0.0,(fract(localTime+0.125)-0.25))*3.0)*0.333;

        spinTime = step31 + localTime;
        //globalTeeth = 0.0 + max(0.0, sin(localTime*3.0))*0.9;
        globalTeeth = rampStep*0.99;
        cut = max(0.48, min(0.77, localTime));
        // --------------------------------------------------------------------------------
        vec2 distAndMat = vec2(0.5, 0.0);
        float t = 0.0;
        //float inc = 0.02;
        float maxDepth = 24.0;
        vec3 pos = vec3(0,0,0);
        marchCount = 0.0;
        // intersect with sphere first as optimization so we don't ray march more than is needed.
        float hit = SphereIntersect(camPos, rayVec, vec3(0.0), 5.6);
        if (hit >= 0.0)
        {
            t = hit;
            // ray marching time
            for (int i = 0; i < 290; i++)   // This is the count of the max times the ray actually marches.
            {
                pos = camPos + rayVec * t;
                // *******************************************************
                // This is _the_ function that defines the "distance field".
                // It's really what makes the scene geometry.
                // *******************************************************
                distAndMat = DistanceToObject(pos);
                // adjust by constant because deformations mess up distance function.
                t += distAndMat.x * 0.7;
                //if (t > maxDepth) break;
                if ((t > maxDepth) || (abs(distAndMat.x) < 0.0025)) break;
                marchCount+= 1.0;
            }
        }
        else
        {
            t = maxDepth + 1.0;
            distAndMat.x = 1000000.0;
        }
        // --------------------------------------------------------------------------------
        // Now that we have done our ray marching, let's put some color on this geometry.

        vec3 sunDir = normalize(vec3(3.93, 10.82, -1.5));
        vec3 finalColor = vec3(0.0);

        // If a ray actually hit the object, let's light it.
        //if (abs(distAndMat.x) < 0.75)
        if (t <= maxDepth)
        {
            // calculate the normal from the distance field. The distance field is a volume, so if you
            // sample the current point and neighboring points, you can use the difference to get
            // the normal.
            vec3 smallVec = vec3(0.005, 0, 0);
            vec3 normalU = vec3(distAndMat.x - DistanceToObject(pos - smallVec.xyy).x,
                               distAndMat.x - DistanceToObject(pos - smallVec.yxy).x,
                               distAndMat.x - DistanceToObject(pos - smallVec.yyx).x);

            vec3 normal = normalize(normalU);

            // calculate 2 ambient occlusion values. One for global stuff and one
            // for local stuff
            float ambientS = 1.0;
            ambientS *= saturate(DistanceToObject(pos + normal * 0.1).x*10.0);
            ambientS *= saturate(DistanceToObject(pos + normal * 0.2).x*5.0);
            ambientS *= saturate(DistanceToObject(pos + normal * 0.4).x*2.5);
            ambientS *= saturate(DistanceToObject(pos + normal * 0.8).x*1.25);
            float ambient = ambientS * saturate(DistanceToObject(pos + normal * 1.6).x*1.25*0.5);
            ambient *= saturate(DistanceToObject(pos + normal * 3.2).x*1.25*0.25);
            ambient *= saturate(DistanceToObject(pos + normal * 6.4).x*1.25*0.125);
            ambient = max(0.035, pow(ambient, 0.3));    // tone down ambient with a pow and min clamp it.
            ambient = saturate(ambient);

            // calculate the reflection vector for highlights
            vec3 ref = reflect(rayVec, normal);
            ref = normalize(ref);

            // Trace a ray for the reflection
            float sunShadow = 1.0;
            float iter = 0.1;
            vec3 nudgePos = pos + normal*0.02;  // don't start tracing too close or inside the object
            for (int i = 0; i < 40; i++)
            {
                float tempDist = DistanceToObject(nudgePos + ref * iter).x;
                sunShadow *= saturate(tempDist*50.0);
                if (tempDist <= 0.0) break;
                //iter *= 1.5;  // constant is more reliable than distance-based
                iter += max(0.00, tempDist)*1.0;
                if (iter > 4.2) break;
            }
            sunShadow = saturate(sunShadow);

            // ------ Calculate texture color ------
            vec3 texColor;
            texColor = vec3(1.0);// vec3(0.65, 0.5, 0.4)*0.1;
            texColor = vec3(0.85, 0.945 - distAndMat.y * 0.15, 0.93 + distAndMat.y * 0.35)*0.951;
            if (distAndMat.y == 6.0) texColor = vec3(0.91, 0.1, 0.41)*10.5;
            //texColor *= mix(vec3(0.3), vec3(1.0), tex3d(pos*0.5, normal).xxx);
            texColor = max(texColor, vec3(0.0));
            texColor *= 0.25;

            // ------ Calculate lighting color ------
            // Start with sun color, standard lighting equation, and shadow
            vec3 lightColor = vec3(0.0);// sunCol * saturate(dot(sunDir, normal)) * sunShadow*14.0;
            // sky color, hemisphere light equation approximation, ambient occlusion
            lightColor += vec3(0.1,0.35,0.95) * (normal.y * 0.5 + 0.5) * ambient * 0.2;
            // ground color - another hemisphere light
            lightColor += vec3(1.0) * ((-normal.y) * 0.5 + 0.5) * ambient * 0.2;


            // finally, apply the light to the texture.
            finalColor = texColor * lightColor;
            //if (distAndMat.y == ceil(mod(localTime, 4.0))) finalColor += vec3(0.0, 0.41, 0.72)*0.925;

            // reflection environment map - this is most of the light
            vec3 refColor = GetEnvColor2(ref, sunDir)*sunShadow;
            finalColor += refColor * 0.35 * ambient;// * sunCol * sunShadow * 9.0 * texColor.g;

            // fog
            finalColor = mix(vec3(1.0, 0.41, 0.41) + vec3(1.0), finalColor, exp(-t*0.0007));
            // visualize length of gradient of distance field to check distance field correctness
            //finalColor = vec3(0.5) * (length(normalU) / smallVec.x);
        }
        else
        {
            finalColor = GetEnvColor2(rayVec, sunDir);// + vec3(0.1, 0.1, 0.1);
        }
        //finalColor += marchCount * vec3(1.0, 0.3, 0.91) * 0.001;

        // vignette?
        //finalColor *= vec3(1.0) * saturate(1.0 - length(uv/2.5));
        //finalColor *= 1.95;

        // output the final color with sqrt for "gamma correction"
        fragColor = vec4(sqrt(clamp(finalColor, 0.0, 1.0)),1.0);
    }
    """

    src_ss = """
    ///////////////////// Simplicity
    // http://www.fractalforums.com/new-theories-and-research/very-simple-formula-for-fractal-patterns/
    float field(in vec3 p) {
        float strength = 7. + .03 * log(1.e-6 + fract(sin(iTime) * 4373.11));
        float accum = 0.;
        float prev = 0.;
        float tw = 0.;
        for (int i = 0; i < 32; ++i) {
            float mag = dot(p, p);
            p = abs(p) / mag + vec3(-.5, -.4, -1.5);
            float w = exp(-float(i) / 7.);
            accum += w * exp(-strength * pow(abs(mag - prev), 2.3));
            tw += w;
            prev = mag;
        }
        return max(0., 5. * accum / tw - .7);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
        vec2 uv = 2. * fragCoord.xy / iResolution.xy - 1.;
        vec2 uvs = uv * iResolution.xy / max(iResolution.x, iResolution.y);
        vec3 p = vec3(uvs / 4., 0) + vec3(1., -1.3, 0.);
        p += .2 * vec3(sin(iTime / 16.), sin(iTime / 12.),  sin(iTime / 128.));
        float t = field(p);
        float v = (1. - exp((abs(uv.x) - 1.) * 6.)) * (1. - exp((abs(uv.y) - 1.) * 6.));
        fragColor = mix(.4, 1., v) * vec4(1.8 * t * t * t, 1.4 * t * t, t, 1.0);
    }
    """

    src_sm = """
    /////////////////// 70s Melt

    #ifdef GL_ES
    precision mediump float;
    #endif
    #define RADIANS 0.017453292519943295

    const int zoom = 40;
    const float brightness = 0.975;
    float fScale = 1.25;

    float cosRange(float degrees, float range, float minimum) {
        return (((1.0 + cos(degrees * RADIANS)) * 0.5) * range) + minimum;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        float time = iTime * 1.25;
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 p  = (2.0*fragCoord.xy-iResolution.xy)/max(iResolution.x,iResolution.y);
        float ct = cosRange(time*5.0, 3.0, 1.1);
        float xBoost = cosRange(time*0.2, 5.0, 5.0);
        float yBoost = cosRange(time*0.1, 10.0, 5.0);

        fScale = cosRange(time * 15.5, 1.25, 0.5);

        for(int i=1;i<zoom;i++) {
            float _i = float(i);
            vec2 newp=p;
            newp.x+=0.25/_i*sin(_i*p.y+time*cos(ct)*0.5/20.0+0.005*_i)*fScale+xBoost;       
            newp.y+=0.25/_i*sin(_i*p.x+time*ct*0.3/40.0+0.03*float(i+15))*fScale+yBoost;
            p=newp;
        }

        vec3 col=vec3(0.5*sin(3.0*p.x)+0.5,0.5*sin(3.0*p.y)+0.5,sin(p.x+p.y));
        col *= brightness;

        // Add border
        float vigAmt = 5.0;
        float vignette = (1.-vigAmt*(uv.y-.5)*(uv.y-.5))*(1.-vigAmt*(uv.x-.5)*(uv.x-.5));
        float extrusion = (col.x + col.y + col.z) / 4.0;
        extrusion *= 1.5;
        extrusion *= vignette;

        fragColor = vec4(col, extrusion);
    }

    /** SHADERDATA
    {
        "title": "70s Melt",
        "description": "Variation of Sine Puke",
        "model": "car"
    }
    */
    """

    src_gr = """
    /////////////////////
    // "GENERATORS REDUX" by Kali 
    // Same fractal as "Ancient Temple" + rotations, improved shading 
    // (better coloring, AO and  shadows), some lighting effects, and a path for the camera  
    // following a liquid metal ball. 

    #define ENABLE_HARD_SHADOWS // turn off to enable faster AO soft shadows 
    //#define ENABLE_VIBRATION
    #define ENABLE_POSTPROCESS // Works better on window view rather than full screen

    #define RAY_STEPS 70
    #define SHADOW_STEPS 50
    #define LIGHT_COLOR vec3(.85,.9,1.)
    #define AMBIENT_COLOR vec3(.8,.83,1.)
    #define FLOOR_COLOR vec3(1.,.7,.9)
    #define ENERGY_COLOR vec3(1.,.7,.4)
    #define BRIGHTNESS .9
    #define GAMMA 1.3
    #define SATURATION .85

    #define detail .00005
    #define t iTime*.25

    vec3 lightdir=normalize(vec3(0.5,-0.3,-1.));
    vec3 ambdir=normalize(vec3(0.,0.,1.));
    const vec3 origin=vec3(0.,3.11,0.);
    vec3 energy=vec3(0.01);
    #ifdef ENABLE_VIBRATION
    float vibration=sin(iTime*60.)*.0013;
    #else
    float vibration=0.;
    #endif
    float det=0.0;
    vec3 pth1;

    mat2 rot(float a) {
        return mat2(cos(a),sin(a),-sin(a),cos(a));  
    }

    vec3 path(float ti) {
    return vec3(sin(ti),.3-sin(ti*.632)*.3,cos(ti*.5))*.5;
    }

    float Sphere(vec3 p, vec3 rd, float r){//A RAY TRACED SPHERE
        float b = dot( -p, rd );
        float inner = b * b - dot( p, p ) + r * r;
        if( inner < 0.0 ) return -1.0;
        return b - sqrt( inner );
    }

    vec2 de(vec3 pos) {
        float hid=0.;
        vec3 tpos=pos;
        tpos.xz=abs(.5-mod(tpos.xz,1.));
        vec4 p=vec4(tpos,1.);
        float y=max(0.,.35-abs(pos.y-3.35))/.35;
        for (int i=0; i<7; i++) {//LOWERED THE ITERS
            p.xyz = abs(p.xyz)-vec3(-0.02,1.98,-0.02);
            p=p*(2.0+vibration*y)/clamp(dot(p.xyz,p.xyz),.4,1.)-vec4(0.5,1.,0.4,0.);
            p.xz*=mat2(-0.416,-0.91,0.91,-0.416);
        }
        float fl=pos.y-3.013;
        float fr=(length(max(abs(p.xyz)-vec3(0.1,5.0,0.1),vec3(0.0)))-0.05)/p.w;//RETURN A RRECT
        //float fr=length(p.xyz)/p.w;
        float d=min(fl,fr);
        d=min(d,-pos.y+3.95);
        if (abs(d-fl)<.001) hid=1.;
        return vec2(d,hid);
    }

    vec3 normal(vec3 p) {
        vec3 e = vec3(0.0,det,0.0);

        return normalize(vec3(
                de(p+e.yxx).x-de(p-e.yxx).x,
                de(p+e.xyx).x-de(p-e.xyx).x,
                de(p+e.xxy).x-de(p-e.xxy).x
                )
            );
    }

    float shadow(vec3 pos, vec3 sdir) {//THIS ONLY RUNS WHEN WITH HARD SHADOWS
        float sh=1.0;
        float totdist =2.0*det;
        float dist=10.;
        float t1=Sphere((pos-.005*sdir)-pth1,-sdir,0.015);
        if (t1>0. && t1<.5) {
            vec3 sphglowNorm=normalize(pos-t1*sdir-pth1);
            sh=1.-pow(max(.0,dot(sphglowNorm,sdir))*1.2,3.);
        }
            for (int steps=0; steps<SHADOW_STEPS; steps++) {
                if (totdist<.6 && dist>detail) {
                    vec3 p = pos - totdist * sdir;
                    dist = de(p).x;
                    sh = min( sh, max(50.*dist/totdist,0.0) );
                    totdist += max(.01,dist);
                }
            }
        return clamp(sh,0.1,1.0);
    }

    float calcAO( const vec3 pos, const vec3 nor ) {
        float aodet=detail*40.;
        float totao = 0.0;
        float sca = 14.0;
        for( int aoi=0; aoi<5; aoi++ ) {
            float hr = aodet*float(aoi*aoi);
            vec3 aopos =  nor * hr + pos;
            float dd = de( aopos ).x;
            totao += -(dd-hr)*sca;
            sca *= 0.7;
        }
        return clamp( 1.0 - 5.0*totao, 0., 1.0 );
    }

    float _texture(vec3 p) {
        p=abs(.5-fract(p*10.));
        vec3 c=vec3(3.);
        float es, l=es=0.;
        for (int i = 0; i < 10; i++) { 
                p = abs(p + c) - abs(p - c) - p; 
                p/= clamp(dot(p, p), .0, 1.);
                p = p* -1.5 + c;
                if ( mod(float(i), 2.) < 1. ) { 
                    float pl = l;
                    l = length(p);
                    es+= exp(-1. / abs(l - pl));
                }
        }
        return es;
    }

    vec3 light(in vec3 p, in vec3 dir, in vec3 n, in float hid) {//PASSING IN THE NORMAL
        #ifdef ENABLE_HARD_SHADOWS
            float sh=shadow(p, lightdir);
        #else
            float sh=calcAO(p,-2.5*lightdir);//USING AO TO MAKE VERY SOFT SHADOWS
        #endif
        float ao=calcAO(p,n);
        float diff=max(0.,dot(lightdir,-n))*sh;
        float y=3.35-p.y;
        vec3 amb=max(.5,dot(dir,-n))*.5*AMBIENT_COLOR;
        if (hid<.5) {
            amb+=max(0.2,dot(vec3(0.,1.,0.),-n))*FLOOR_COLOR*pow(max(0.,.2-abs(3.-p.y))/.2,1.5)*2.;
            amb+=energy*pow(max(0.,.4-abs(y))/.4,2.)*max(0.2,dot(vec3(0.,-sign(y),0.),-n))*2.;
        }
        vec3 r = reflect(lightdir,n);
        float spec=pow(max(0.,dot(dir,-r))*sh,10.);
        vec3 col;
        float energysource=pow(max(0.,.04-abs(y))/.04,4.)*2.;
        if (hid>1.5) {col=vec3(1.); spec=spec*spec;}
        else{
            float k=_texture(p)*.23+.2; 
            k=min(k,1.5-energysource);
            col=mix(vec3(k,k*k,k*k*k),vec3(k),.3);
            if (abs(hid-1.)<.001) col*=FLOOR_COLOR*1.3;
        }
        col=col*(amb+diff*LIGHT_COLOR)+spec*LIGHT_COLOR;    
        if (hid<.5) { 
            col=max(col,energy*2.*energysource);
        }
        col*=min(1.,ao+length(energy)*.5*max(0.,.1-abs(y))/.1);
        return col;
    }

    vec3 raymarch(in vec3 from, in vec3 dir) 

    {
        float ey=mod(t*.5,1.);
        float glow,eglow,ref,sphdist,totdist=glow=eglow=ref=sphdist=0.;
        vec2 d=vec2(1.,0.);
        vec3 p, col=vec3(0.);
        vec3 origdir=dir,origfrom=from,sphNorm;

        //FAKING THE SQUISHY BALL BY MOVING A RAY TRACED BALL
        vec3 wob=cos(dir*500.0*length(from-pth1)+(from-pth1)*250.+iTime*10.)*0.0005;
        float t1=Sphere(from-pth1+wob,dir,0.015);
        float tg=Sphere(from-pth1+wob,dir,0.02);
        if(t1>0.){
            ref=1.0;from+=t1*dir;sphdist=t1;
            sphNorm=normalize(from-pth1+wob);
            dir=reflect(dir,sphNorm);
        }
        else if (tg>0.) { 
            vec3 sphglowNorm=normalize(from+tg*dir-pth1+wob);
            glow+=pow(max(0.,dot(sphglowNorm,-dir)),5.);
        };

        for (int i=0; i<RAY_STEPS; i++) {
            if (d.x>det && totdist<3.0) {
                p=from+totdist*dir;
                d=de(p);
                det=detail*(1.+totdist*60.)*(1.+ref*5.);
                totdist+=d.x; 
                energy=ENERGY_COLOR*(1.5+sin(iTime*20.+p.z*10.))*.25;
                if(d.x<0.015)glow+=max(0.,.015-d.x)*exp(-totdist);
                if (d.y<.5 && d.x<0.03){//ONLY DOING THE GLOW WHEN IT IS CLOSE ENOUGH
                    float glw=min(abs(3.35-p.y-ey),abs(3.35-p.y+ey));//2 glows at once
                    eglow+=max(0.,.03-d.x)/.03*
                    (pow(max(0.,.05-glw)/.05,5.)
                    +pow(max(0.,.15-abs(3.35-p.y))/.15,8.))*1.5;
                }
            }
        }
        float l=pow(max(0.,dot(normalize(-dir.xz),normalize(lightdir.xz))),2.);
        l*=max(0.2,dot(-dir,lightdir));
        vec3 backg=.5*(1.2-l)+LIGHT_COLOR*l*.7;
        backg*=AMBIENT_COLOR;
        if (d.x<=det) {
            vec3 norm=normal(p-abs(d.x-det)*dir);//DO THE NORMAL CALC OUTSIDE OF LIGHTING (since we already have the sphere normal)
            col=light(p-abs(d.x-det)*dir, dir, norm, d.y)*exp(-.2*totdist*totdist); 
            col = mix(col, backg, 1.0-exp(-1.*pow(totdist,1.5)));
        } else { 
            col=backg;
        }
        vec3 lglow=LIGHT_COLOR*pow(l,30.)*.5;
        col+=glow*(backg+lglow)*1.3;
        col+=pow(eglow,2.)*energy*.015;
        col+=lglow*min(1.,totdist*totdist*.3);
        if (ref>0.5) {
            vec3 sphlight=light(origfrom+sphdist*origdir,origdir,sphNorm,2.);
            col=mix(col*.3+sphlight*.7,backg,1.0-exp(-1.*pow(sphdist,1.5)));
        }
        return col; 
    }

    vec3 move(inout mat2 rotview1,inout mat2 rotview2) {
        vec3 go=path(t);
        vec3 adv=path(t+.7);
        vec3 advec=normalize(adv-go);
        float an=atan(advec.x,advec.z);
        rotview1=mat2(cos(an),sin(an),-sin(an),cos(an));
        an=advec.y*1.7;
        rotview2=mat2(cos(an),sin(an),-sin(an),cos(an));
        return go;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        pth1 = path(t+.3)+origin+vec3(0.,.01,0.);
        vec2 uv = fragCoord.xy / iResolution.xy*2.-1.;
        vec2 uv2=uv;
    #ifdef ENABLE_POSTPROCESS
        uv*=1.+pow(length(uv2*uv2*uv2*uv2),4.)*.07;
    #endif
        uv.y*=iResolution.y/iResolution.x;
        vec2 mouse=(iMouse.xy/iResolution.xy-.5)*3.;
        if (iMouse.z<1.) mouse=vec2(0.);
        mat2 rotview1, rotview2;
        vec3 from=origin+move(rotview1,rotview2);
        vec3 dir=normalize(vec3(uv*.8,1.));
        dir.yz*=rot(mouse.y);
        dir.xz*=rot(mouse.x);
        dir.yz*=rotview2;
        dir.xz*=rotview1;
        vec3 color=raymarch(from,dir); 
        color=clamp(color,vec3(.0),vec3(1.));
        color=pow(color,vec3(GAMMA))*BRIGHTNESS;
        color=mix(vec3(length(color)),color,SATURATION);
    #ifdef ENABLE_POSTPROCESS
        vec3 rain=pow(texture(iChannel0,uv2+iTime*7.25468).rgb,vec3(1.5));
        color=mix(rain,color,clamp(iTime*.5-.5,0.,1.));
        color*=1.-pow(length(uv2*uv2*uv2*uv2)*1.1,6.);
        uv2.y *= iResolution.y / 360.0;
        color.r*=(.5+abs(.5-mod(uv2.y     ,.021)/.021)*.5)*1.5;
        color.g*=(.5+abs(.5-mod(uv2.y+.007,.021)/.021)*.5)*1.5;
        color.b*=(.5+abs(.5-mod(uv2.y+.014,.021)/.021)*.5)*1.5;
        color*=.9+rain*.35;
    #endif
        fragColor = vec4(color,1.);
    }
    """

    src_wt = """
    /////////////////////water turbulence
    // Found this on GLSL sandbox. I really liked it, changed a few things and made it tileable.
    // :)
    // by David Hoskins.
    // Original water turbulence effect by joltz0r
    // Redefine below to see the tiling...
    //#define SHOW_TILING

    #define TAU 6.28318530718
    #define MAX_ITER 5

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) 
    {
        float time = iTime * .5+23.0;
        // uv should be the 0-1 uv of texture...
        vec2 uv = fragCoord.xy / iResolution.xy;

    #ifdef SHOW_TILING
        vec2 p = mod(uv*TAU*2.0, TAU)-250.0;
    #else
        vec2 p = mod(uv*TAU, TAU)-250.0;
    #endif
        vec2 i = vec2(p);
        float c = 1.0;
        float inten = .005;

        for (int n = 0; n < MAX_ITER; n++) 
        {
            float t = time * (1.0 - (3.5 / float(n+1)));
            i = p + vec2(cos(t - i.x) + sin(t + i.y), sin(t - i.y) + cos(t + i.x));
            c += 1.0/length(vec2(p.x / (sin(i.x+t)/inten),p.y / (cos(i.y+t)/inten)));
        }
        c /= float(MAX_ITER);
        c = 1.17-pow(c, 1.4);
        vec3 colour = vec3(pow(abs(c), 8.0));
        colour = clamp(colour + vec3(0.0, 0.35, 0.5), 0.0, 1.0);

        #ifdef SHOW_TILING
        // Flash tile borders...
        vec2 pixel = 2.0 / iResolution.xy;
        uv *= 2.0;
        float f = floor(mod(iTime*.5, 2.0));    // Flash value.
        vec2 first = step(pixel, uv) * f;           // Rule out first screen pixels and flash.
        uv  = step(fract(uv), pixel);               // Add one line of pixels per tile.
        colour = mix(colour, vec3(1.0, 1.0, 0.0), (uv.x + uv.y) * first.x * first.y); // Yellow line
        #endif

        fragColor = vec4(colour, 1.0);
    }
    """

    src_pw = """
    /////////////////////
    /*
        Perspex Web Lattice
        -------------------
        I felt that Shadertoy didn't have enough Voronoi examples, so I made another one. :) I'm
        not exactly sure what it's supposed to be... My best guess is that an Alien race with no 
        common sense designed a monitor system with physics defying materials. :)

        Technically speaking, there's not much to it. It's just some raymarched 2nd order Voronoi.
        The dark perspex-looking web lattice is created by manipulating the Voronoi value slightly 
        and giving the effected region an ID value so as to color it differently, but that's about
        it. The details are contained in the "heightMap" function.

        There's also some subtle edge detection in order to give the example a slight comic look. 
        3D geometric edge detection doesn't really differ a great deal in concept from 2D pixel 
        edge detection, but it obviously involves more processing power. However, it's possible to 
        combine the edge detection with the normal calculation and virtually get it for free. Kali 
        uses it to great effect in his "Fractal Land" example. It's also possible to do a
        tetrahedral version... I think Nimitz and some others may have done it already. Anyway, 
        you can see how it's done in the "nr" (normal) function.

        Geometric edge related examples:
        Fractal Land - Kali
        https://www.shadertoy.com/view/XsBXWt
        Rotating Cubes - Shau
        https://www.shadertoy.com/view/4sGSRc

        Voronoi mesh related:
        // I haven't really looked into this, but it's interesting.
        Weaved Voronoi - FabriceNeyret2 
        https://www.shadertoy.com/view/ltsXRM
    */

    #define FAR 2.

    int id = 0; // Object ID - Red perspex: 0; Black lattice: 1.

    // Tri-Planar blending function. Based on an old Nvidia writeup:
    // GPU Gems 3 - Ryan Geiss: https://developer.nvidia.com/gpugems/GPUGems3/gpugems3_ch01.html
    vec3 tex3D( sampler2D tex, in vec3 p, in vec3 n ){
       
        n = max((abs(n) - .2), .001);
        n /= (n.x + n.y + n.z ); // Roughly normalized.
        
        p = (texture(tex, p.yz)*n.x + texture(tex, p.zx)*n.y + texture(tex, p.xy)*n.z).xyz;
        
        // Loose sRGB to RGB conversion to counter final value gamma correction...
        // in case you're wondering.
        return p*p;
    }

    // Compact, self-contained version of IQ's 3D value noise function. I have a transparent noise
    // example that explains it, if you require it.
    float n3D(vec3 p){
        const vec3 s = vec3(7, 157, 113);
        vec3 ip = floor(p); p -= ip; 
        vec4 h = vec4(0., s.yz, s.y + s.z) + dot(ip, s);
        p = p*p*(3. - 2.*p); //p *= p*p*(p*(p * 6. - 15.) + 10.);
        h = mix(fract(sin(h)*43758.5453), fract(sin(h + s.x)*43758.5453), p.x);
        h.xy = mix(h.xz, h.yw, p.y);
        return mix(h.x, h.y, p.z); // Range: [0, 1].
    }

    // vec2 to vec2 hash.
    vec2 hash22(vec2 p) {

        // Faster, but doesn't disperse things quite as nicely. However, when framerate
        // is an issue, and it often is, this is a good one to use. Basically, it's a tweaked 
        // amalgamation I put together, based on a couple of other random algorithms I've 
        // seen around... so use it with caution, because I make a tonne of mistakes. :)

        float n = sin(dot(p, vec2(41, 289)));

        //return fract(vec2(262144, 32768)*n); 
        // Animated.

        p = fract(vec2(262144, 32768)*n); 

        // Note the ".45," insted of ".5" that you'd expect to see. When edging, it can open 
        // up the cells ever so slightly for a more even spread. In fact, lower numbers work 
        // even better, but then the random movement would become too restricted. Zero would 
        // give you square cells.

        return sin( p*6.2831853 + iTime )*.45 + .5; 
    }

    // 2D 2nd-order Voronoi: Obviously, this is just a rehash of IQ's original. I've tidied
    // up those if-statements. Since there's less writing, it should go faster. That's how 
    // it works, right? :)
    //
    float Voronoi(in vec2 p){

        vec2 g = floor(p), o; p -= g;

        vec3 d = vec3(1); // 1.4, etc. "d.z" holds the distance comparison value.
        
        for(int y = -1; y <= 1; y++){
            for(int x = -1; x <= 1; x++){
                
                o = vec2(x, y);
                o += hash22(g + o) - p;
                
                d.z = dot(o, o); 
                // More distance metrics.
                //o = abs(o);
                //d.z = max(o.x*.8666 + o.y*.5, o.y);// 
                //d.z = max(o.x, o.y);
                //d.z = (o.x*.7 + o.y*.7);
                
                d.y = max(d.x, min(d.y, d.z));
                d.x = min(d.x, d.z); 
            }
        }

        return max(d.y/1.2 - d.x*1., 0.)/1.2;
        //return d.y - d.x; // return 1.-d.x; // etc.
    }

    // The height map values. In this case, it's just a Voronoi variation. By the way, I could
    // optimize this a lot further, but it's not a particularly taxing distance function, so
    // I've left it in a more readable state.
    float heightMap(vec3 p){
        id =0;
        float c = Voronoi(p.xy*4.); // The fiery bit.

        // For lower values, reverse the surface direction, smooth, then
        // give it an ID value of one. Ie: this is the black web-like
        // portion of the surface.

        if (c<.07) {c = smoothstep(0.7, 1., 1.-c)*.2; id = 1; }
        return c;
    }

    // Standard back plane height map. Put the plane at vec3(0, 0, 1), then add some height values.
    // Obviously, you don't want the values to be too large. The one's here account for about 10%
    // of the distance between the plane and the camera.
    float m(vec3 p){
        float h = heightMap(p); // texture(iChannel0, p.xy/2.).x; // Texture work too.

        return 1. - p.z - h*.1;
    }

    /*
    // Tetrahedral normal, to save a couple of "map" calls. Courtesy of IQ.
    vec3 nr(in vec3 p){

        // Note the slightly increased sampling distance, to alleviate artifacts due to hit point inaccuracies.
        vec2 e = vec2(0.005, -0.005); 
        return normalize(e.xyy * m(p + e.xyy) + e.yyx * m(p + e.yyx) + e.yxy * m(p + e.yxy) + e.xxx * m(p + e.xxx));
    }
    */

    /*
    // Standard normal function - for comparison with the one below.
    vec3 nr(in vec3 p) {
        const vec2 e = vec2(0.005, 0);
        return normalize(vec3(m(p + e.xyy) - m(p - e.xyy), m(p + e.yxy) - m(p - e.yxy), m(p + e.yyx) - m(p - e.yyx)));
    }
    */

    // The normal function with some edge detection rolled into it.
    vec3 nr(vec3 p, inout float edge) { 

        vec2 e = vec2(.005, 0);

        // Take some distance function measurements from either side of the hit point on all three axes.
        float d1 = m(p + e.xyy), d2 = m(p - e.xyy);
        float d3 = m(p + e.yxy), d4 = m(p - e.yxy);
        float d5 = m(p + e.yyx), d6 = m(p - e.yyx);
        float d = m(p)*2.;  // The hit point itself - Doubled to cut down on calculations. See below.
         
        // Edges - Take a geometry measurement from either side of the hit point. Average them, then see how
        // much the value differs from the hit point itself. Do this for X, Y and Z directions. Here, the sum
        // is used for the overall difference, but there are other ways. Note that it's mainly sharp surface 
        // curves that register a discernible difference.
        edge = abs(d1 + d2 - d) + abs(d3 + d4 - d) + abs(d5 + d6 - d);
        //edge = max(max(abs(d1 + d2 - d), abs(d3 + d4 - d)), abs(d5 + d6 - d)); // Etc.
        
        // Once you have an edge value, it needs to normalized, and smoothed if possible. How you 
        // do that is up to you. This is what I came up with for now, but I might tweak it later.
        edge = smoothstep(0., 1., sqrt(edge/e.x*2.));

        // Return the normal.
        // Standard, normalized gradient mearsurement.
        return normalize(vec3(d1 - d2, d3 - d4, d5 - d6));
    }

    /*
    // I keep a collection of occlusion routines... OK, that sounded really nerdy. :)
    // Anyway, I like this one. I'm assuming it's based on IQ's original.
    float cAO(in vec3 p, in vec3 n)
    {
        float sca = 3., occ = 0.;
        for(float i=0.; i<5.; i++){
        
            float hr = .01 + i*.5/4.;
            float dd = m(n * hr + p);
            occ += (hr - dd)*sca;
            sca *= 0.7;
        }
        return clamp(1.0 - occ, 0., 1.);
    }
    */

    /*
    // Standard hue rotation formula... compacted down a bit.
    vec3 rotHue(vec3 p, float a){

        vec2 cs = sin(vec2(1.570796, 0) + a);

        mat3 hr = mat3(0.299,  0.587,  0.114,  0.299,  0.587,  0.114,  0.299,  0.587,  0.114) +
                  mat3(0.701, -0.587, -0.114, -0.299,  0.413, -0.114, -0.300, -0.588,  0.886) * cs.x +
                  mat3(0.168,  0.330, -0.497, -0.328,  0.035,  0.292,  1.250, -1.050, -0.203) * cs.y;

        return clamp(p*hr, 0., 1.);
    }
    */
    // Simple environment mapping. Pass the reflected vector in and create some
    // colored noise with it. The normal is redundant here, but it can be used
    // to pass into a 3D texture mapping function to produce some interesting
    // environmental reflections.
    //
    // More sophisticated environment mapping:
    // UI easy to integrate - XT95    
    // https://www.shadertoy.com/view/ldKSDm
    vec3 eMap(vec3 rd, vec3 sn){

        vec3 sRd = rd; // Save rd, just for some mixing at the end.

        // Add a time component, scale, then pass into the noise function.
        rd.xy -= iTime*.25;
        rd *= 3.;

        //vec3 tx = tex3D(iChannel0, rd/3., sn);
        //float c = dot(tx*tx, vec3(.299, .587, .114));

        float c = n3D(rd)*.57 + n3D(rd*2.)*.28 + n3D(rd*4.)*.15; // Noise value.
        c = smoothstep(0.5, 1., c); // Darken and add contast for more of a spotlight look.

        //vec3 col = vec3(c, c*c, c*c*c*c).zyx; // Simple, warm coloring.
        vec3 col = vec3(min(c*1.5, 1.), pow(c, 2.5), pow(c, 12.)).zyx; // More color.

        // Mix in some more red to tone it down and return.
        return mix(col, col.yzx, sRd*.25+.25); 
    }

    void mainImage(out vec4 c, vec2 u){

        // Unit direction ray, camera origin and light position.
        vec3 r = normalize(vec3(u - iResolution.xy*.5, iResolution.y)), 
             o = vec3(0), l = o + vec3(0, 0, -1);

        // Rotate the canvas. Note that sine and cosine are kind of rolled into one.
        vec2 a = sin(vec2(1.570796, 0) + iTime/8.); // Fabrice's observation.
        r.xy = mat2(a, -a.y, a.x) * r.xy;

        // Standard raymarching routine. Raymarching a slightly perturbed back plane front-on
        // doesn't usually require many iterations. Unless you rely on your GPU for warmth,
        // this is a good thing. :)
        float d, t = 0.;

        for(int i=0; i<32;i++){
            d = m(o + r*t);
            // There isn't really a far plane to go beyond, but it's there anyway.
            if(abs(d)<0.001 || t>FAR) break;
            t += d*.7;
        }

        t = min(t, FAR);

        // Set the initial scene color to black.
        c = vec4(0);

        float edge = 0.; // Edge value - to be passed into the normal.

        if(t<FAR){

            vec3 p = o + r*t, n = nr(p, edge);

            l -= p; // Light to surface vector. Ie: Light direction vector.
            d = max(length(l), 0.001); // Light to surface distance.
            l /= d; // Normalizing the light direction vector.

            // Obtain the height map (destorted Voronoi) value, and use it to slightly
            // shade the surface. Gives a more shadowy appearance.
            float hm = heightMap(p);
            
            // Texture value at the surface. Use the heighmap value above to distort the
            // texture a bit.
            vec3 tx = tex3D(iChannel0, (p*2. + hm*.2), n);
            //tx = floor(tx*15.999)/15.; // Quantized cartoony colors, if you get bored enough.

            c.xyz = vec3(1.)*(hm*.8 + .2); // Applying the shading to the final color.

            c.xyz *= vec3(1.5)*tx; // Multiplying by the texture value and lightening.

            // Color the cell part with a fiery (I incorrectly spell it firey all the time) 
            // palette and the latticey web thing a very dark color.
            //
            c.x = dot(c.xyz, vec3(.299, .587, .114)); // Grayscale.
            if (id==0) c.xyz *= vec3(min(c.x*1.5, 1.), pow(c.x, 5.), pow(c.x, 24.))*2.;
            else c.xyz *= .1;

            // Hue rotation, for anyone who's interested.
            //c.xyz = rotHue(c.xyz, mod(iTime/16., 6.283));

            float df = max(dot(l, n), 0.); // Diffuse.
            float sp = pow(max(dot(reflect(-l, n), -r), 0.), 32.); // Specular.

            if(id == 1) sp *= sp; // Increase specularity on the dark lattice.

            // Applying some diffuse and specular lighting to the surface.
            c.xyz = c.xyz*(df + .75) + vec3(1, .97, .92)*sp + vec3(.5, .7, 1)*pow(sp, 32.);

            // Add the fake environmapping. Give the dark surface less reflectivity.
            vec3 em = eMap(reflect(r, n), n); // Fake environment mapping.
            if(id == 1) em *= .5;
            c.xyz += em;

            // Edges.
            //if(id == 0)c.xyz += edge*.1; // Lighter edges.
            c.xyz *= 1. - edge*.8; // Darker edges.
            
            // Attenuation, based on light to surface distance.    
            c.xyz *= 1./(1. + d*d*.125);

            // AO - The effect is probably too subtle, in this case, so we may as well
            // save some cycles.
            //c.xyz *= cAO(p, n);
        }

        // Vignette.
        //vec2 uv = u/iResolution.xy;
        //c.xyz = mix(c.xyz, vec3(0, 0, .5), .1 -pow(16.*uv.x*uv.y*(1.-uv.x)*(1.-uv.y), 0.25)*.1);
        // Apply some statistically unlikely (but close enough) 2.0 gamma correction. :)
        c = vec4(sqrt(clamp(c.xyz, 0., 1.)), 1.);
    }
    """

    src_mm = """
    /////////////////// monochrome

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){
        vec2 uv =  (2.0 * fragCoord - iResolution.xy) / min(iResolution.x, iResolution.y);

        for(float i = 1.0; i < 10.0; i++){
            uv.x += 0.6 / i * cos(i * 2.5* uv.y + iTime/10);
            uv.y += 0.6 / i * cos(i * 1.5 * uv.x + iTime/10);
        }
        
        fragColor = vec4(vec3(0.1)/abs(sin(iTime-uv.y-uv.x)),0.5);
    }
    """

    src_gu = """
    ///////////////////Galaxy of Universes
    // https://www.shadertoy.com/view/MdXSzS
    // The Big Bang - just a small explosion somewhere in a massive Galaxy of Universes.
    // Outside of this there's a massive galaxy of 'Galaxy of Universes'... etc etc. :D
    // To fake a perspective it takes advantage of the screen being wider than it is tall.

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord.xy / iResolution.xy) - .5;
        float t = iTime * .1 + ((.25 + .05 * sin(iTime * .1))/(length(uv.xy) + .07)) * 2.2;
        float si = sin(t);
        float co = cos(t);
        mat2 ma = mat2(co, si, -si, co);

        float v1, v2, v3;
        v1 = v2 = v3 = 0.0;

        float s = 0.0;
        for (int i = 0; i < 90; i++)
        {
            vec3 p = s * vec3(uv, 0.0);
            p.xy *= ma;
            p += vec3(.22, .3, s - 1.5 - sin(iTime * .13) * .1);
            for (int i = 0; i < 8; i++) p = abs(p) / dot(p,p) - 0.659;
            v1 += dot(p,p) * .0015 * (1.8 + sin(length(uv.xy * 13.0) + .5  - iTime * .2));
            v2 += dot(p,p) * .0013 * (1.5 + sin(length(uv.xy * 14.5) + 1.2 - iTime * .3));
            v3 += length(p.xy*10.) * .0003;
            s  += .035;
        }

        float len = length(uv);
        v1 *= smoothstep(.7, .0, len);
        v2 *= smoothstep(.5, .0, len);
        v3 *= smoothstep(.9, .0, len);

        vec3 col = vec3( v3 * (1.5 + sin(iTime * .2) * .4),
                        (v1 + v3) * .3,
                         v2) + smoothstep(0.2, .0, len) * .85 + smoothstep(.0, .6, v3) * .3;

        fragColor=vec4(min(pow(abs(col), vec3(1.2)), 1.0), 1.0);
    }
    """

    src_ar = """
    ///////////////////Auroras
    // Auroras by nimitz 2017 (twitter: @stormoid)
    // License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
    // Contact the author for other licensing options
    /*
        There are two main hurdles I encountered rendering this effect. 
        First, the nature of the texture that needs to be generated to get a believable effect
        needs to be very specific, with large scale band-like structures, small scale non-smooth variations
        to create the trail-like effect, a method for animating said texture smoothly and finally doing all
        of this cheaply enough to be able to evaluate it several times per fragment/pixel.

        The second obstacle is the need to render a large volume while keeping the computational cost low.
        Since the effect requires the trails to extend way up in the atmosphere to look good, this means
        that the evaluated volume cannot be as constrained as with cloud effects. My solution was to make
        the sample stride increase polynomially, which works very well as long as the trails are lower opcaity than
        the rest of the effect. Which is always the case for auroras.

        After that, there were some issues with getting the correct emission curves and removing banding at lowered
        sample densities, this was fixed by a combination of sample number influenced dithering and slight sample blending.

        N.B. the base setup is from an old shader and ideally the effect would take an arbitrary ray origin and
        direction. But this was not required for this demo and would be trivial to fix.
    */

    #define time iTime

    mat2 mm2(in float a){float c = cos(a), s = sin(a);return mat2(c,s,-s,c);}
    mat2 m2 = mat2(0.95534, 0.29552, -0.29552, 0.95534);
    float tri(in float x){return clamp(abs(fract(x)-.5),0.01,0.49);}
    vec2 tri2(in vec2 p){return vec2(tri(p.x)+tri(p.y),tri(p.y+tri(p.x)));}

    float triNoise2d(in vec2 p, float spd)
    {
        float z=1.8;
        float z2=2.5;
        float rz = 0.;
        p *= mm2(p.x*0.06);
        vec2 bp = p;
        for (float i=0.; i<5.; i++ )
        {
            vec2 dg = tri2(bp*1.85)*.75;
            dg *= mm2(time*spd);
            p -= dg/z2;

            bp *= 1.3;
            z2 *= .45;
            z *= .42;
            p *= 1.21 + (rz-1.0)*.02;
            
            rz += tri(p.x+tri(p.y))*z;
            p*= -m2;
        }
        return clamp(1./pow(rz*29., 1.3),0.,.55);
    }

    float hash21(in vec2 n){ return fract(sin(dot(n, vec2(12.9898, 4.1414))) * 43758.5453); }
    vec4 aurora(vec3 ro, vec3 rd)
    {
        vec4 col = vec4(0);
        vec4 avgCol = vec4(0);
        
        for(float i=0.;i<50.;i++)
        {
            float of = 0.006*hash21(gl_FragCoord.xy)*smoothstep(0.,15., i);
            float pt = ((.8+pow(i,1.4)*.002)-ro.y)/(rd.y*2.+0.4);
            pt -= of;
            vec3 bpos = ro + pt*rd;
            vec2 p = bpos.zx;
            float rzt = triNoise2d(p, 0.06);
            vec4 col2 = vec4(0,0,0, rzt);
            col2.rgb = (sin(1.-vec3(2.15,-.5, 1.2)+i*0.043)*0.5+0.5)*rzt;
            avgCol =  mix(avgCol, col2, .5);
            col += avgCol*exp2(-i*0.065 - 2.5)*smoothstep(0.,5., i);
        }

        col *= (clamp(rd.y*15.+.4,0.,1.));

        //return clamp(pow(col,vec4(1.3))*1.5,0.,1.);
        //return clamp(pow(col,vec4(1.7))*2.,0.,1.);
        //return clamp(pow(col,vec4(1.5))*2.5,0.,1.);
        //return clamp(pow(col,vec4(1.8))*1.5,0.,1.);

        //return smoothstep(0.,1.1,pow(col,vec4(1.))*1.5);
        return col*1.8;
        //return pow(col,vec4(1.))*2.
    }

    //-------------------Background and Stars--------------------

    vec3 nmzHash33(vec3 q)
    {
        uvec3 p = uvec3(ivec3(q));
        p = p*uvec3(374761393U, 1103515245U, 668265263U) + p.zxy + p.yzx;
        p = p.yzx*(p.zxy^(p >> 3U));
        return vec3(p^(p >> 16U))*(1.0/vec3(0xffffffffU));
    }

    vec3 stars(in vec3 p)
    {
        vec3 c = vec3(0.);
        float res = iResolution.x*1.;
        
        for (float i=0.;i<4.;i++)
        {
            vec3 q = fract(p*(.15*res))-0.5;
            vec3 id = floor(p*(.15*res));
            vec2 rn = nmzHash33(id).xy;
            float c2 = 1.-smoothstep(0.,.6,length(q));
            c2 *= step(rn.x,.0005+i*i*0.001);
            c += c2*(mix(vec3(1.0,0.49,0.1),vec3(0.75,0.9,1.),rn.y)*0.1+0.9);
            p *= 1.3;
        }
        return c*c*.8;
    }

    vec3 bg(in vec3 rd)
    {
        float sd = dot(normalize(vec3(-0.5, -0.6, 0.9)), rd)*0.5+0.5;
        sd = pow(sd, 5.);
        vec3 col = mix(vec3(0.05,0.1,0.2), vec3(0.1,0.05,0.2), sd);
        return col*.63;
    }
    //-----------------------------------------------------------

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 q = fragCoord.xy / iResolution.xy;
        vec2 p = q - 0.5;
        p.x*=iResolution.x/iResolution.y;
        
        vec3 ro = vec3(0,0,-6.7);
        vec3 rd = normalize(vec3(p,1.3));
        vec2 mo = iMouse.xy / iResolution.xy-.5;
        mo = (mo==vec2(-.5))?mo=vec2(-0.1,0.1):mo;
        mo.x *= iResolution.x/iResolution.y;
        rd.yz *= mm2(mo.y);
        rd.xz *= mm2(mo.x + sin(time*0.05)*0.2);
        
        vec3 col = vec3(0.);
        vec3 brd = rd;
        float fade = smoothstep(0.,0.01,abs(brd.y))*0.1+0.9;
        
        col = bg(rd)*fade;
        
        if (rd.y > 0.){
            vec4 aur = smoothstep(0.,1.5,aurora(ro,rd))*fade;
            col += stars(rd);
            col = col*(1.-aur.a) + aur.rgb;
        }
        else //Reflections
        {
            rd.y = abs(rd.y);
            col = bg(rd)*fade*0.6;
            vec4 aur = smoothstep(0.0,2.5,aurora(ro,rd));
            col += stars(rd)*0.1;
            col = col*(1.-aur.a) + aur.rgb;
            vec3 pos = ro + ((0.5-ro.y)/rd.y)*rd;
            float nz2 = triNoise2d(pos.xz*vec2(.5,.7), 0.);
            col += mix(vec3(0.2,0.25,0.5)*0.08,vec3(0.3,0.3,0.5)*0.7, nz2*0.4);
        }
        fragColor = vec4(col, 1.);
    }
    """

    src_mr = """
    ///////////////////Super Mario Bros. by HLorenzi
    // Super Mario Bros. by HLorenzi
    // If it does not run at 60 FPS,
    // try pausing/turning off the music!
    // Uncomment for totally random level!
    // Just to show off Mario's dynamic movements :P
    //#define TOTALLY_RANDOM_LEVEL 1
    // Positions to start and end Mario simulation (relative to screen position)
    // You can try changing these! (the difference between the two should be a multiple of 4)
    // Put startX too close to endX, and Mario'll experience jittering!

    #define startX  0.0
    #define endX   80.0

    #define RGB(r,g,b) vec4(float(r)/255.0,float(g)/255.0,float(b)/255.0,1.0)

    #define SPRROW(x,a,b,c,d,e,f,g,h, i,j,k,l,m,n,o,p) (x <= 7 ? SPRROW_H(a,b,c,d,e,f,g,h) : SPRROW_H(i,j,k,l,m,n,o,p))
    #define SPRROW_H(a,b,c,d,e,f,g,h) (a+4.0*(b+4.0*(c+4.0*(d+4.0*(e+4.0*(f+4.0*(g+4.0*(h))))))))
    #define SECROW(x,a,b,c,d,e,f,g,h) (x <= 3 ? SECROW_H(a,b,c,d) : SECROW_H(e,f,g,h))
    #define SECROW_H(a,b,c,d) (a+8.0*(b+8.0*(c+8.0*(d))))
    #define SELECT(x,i) mod(floor(i/pow(4.0,float(x))),4.0)
    #define SELECTSEC(x,i) mod(floor(i/pow(8.0,float(x))),8.0)

    float rand(vec2 co)
    {
        return fract(sin(dot(co.xy ,vec2(12.9898,78.233))) * 43758.5453);
    }

    vec4 sprGround(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,1.,0.,0.,0.,0.,0.,0.,0., 0.,2.,1.,0.,0.,0.,0.,1.);
        if (y == 14) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,1.,1.,1.,1.,2.);
        if (y == 13) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,1.,1.,1.,1.,2.);
        if (y == 12) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,1.,1.,1.,1.,2.);
        if (y == 11) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,2.,1.,1.,1.,2.);
        if (y == 10) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,1.,2.,2.,2.,2.,1.);
        if (y ==  9) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,0.,0.,0.,0.,2.);
        if (y ==  8) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,1.,1.,1.,1.,2.);
        
        if (y ==  7) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,1.,1.,1.,1.,2.);
        if (y ==  6) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,2.,0.,1.,1.,1.,1.,2.);
        if (y ==  5) col = SPRROW(x,2.,2.,1.,1.,1.,1.,1.,1., 2.,0.,1.,1.,1.,1.,1.,2.);
        if (y ==  4) col = SPRROW(x,0.,0.,2.,2.,1.,1.,1.,1., 2.,0.,1.,1.,1.,1.,1.,2.);
        if (y ==  3) col = SPRROW(x,0.,1.,0.,0.,2.,2.,2.,2., 0.,1.,1.,1.,1.,1.,1.,2.);
        if (y ==  2) col = SPRROW(x,0.,1.,1.,1.,0.,0.,0.,2., 0.,1.,1.,1.,1.,1.,1.,2.);
        if (y ==  1) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,2., 0.,1.,1.,1.,1.,1.,2.,2.);
        if (y ==  0) col = SPRROW(x,1.,2.,2.,2.,2.,2.,2.,1., 0.,2.,2.,2.,2.,2.,2.,1.);
        
        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(247,214,181);
        if (col == 1.0) return RGB(231,90,16);
        return RGB(0,0,0);
    }

    vec4 sprQuestionBlock(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,3.,0.,0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.,0.,3.);
        if (y == 14) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,2.);
        if (y == 13) col = SPRROW(x,0.,1.,2.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,2.,1.,2.);
        if (y == 12) col = SPRROW(x,0.,1.,1.,1.,1.,0.,0.,0., 0.,0.,1.,1.,1.,1.,1.,2.);
        if (y == 11) col = SPRROW(x,0.,1.,1.,1.,0.,0.,2.,2., 2.,0.,0.,1.,1.,1.,1.,2.);
        if (y == 10) col = SPRROW(x,0.,1.,1.,1.,0.,0.,2.,1., 1.,0.,0.,2.,1.,1.,1.,2.);
        if (y ==  9) col = SPRROW(x,0.,1.,1.,1.,0.,0.,2.,1., 1.,0.,0.,2.,1.,1.,1.,2.);
        if (y ==  8) col = SPRROW(x,0.,1.,1.,1.,1.,2.,2.,1., 0.,0.,0.,2.,1.,1.,1.,2.);
        
        if (y ==  7) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,0., 0.,2.,2.,2.,1.,1.,1.,2.);
        if (y ==  6) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,0., 0.,2.,1.,1.,1.,1.,1.,2.);
        if (y ==  5) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 2.,2.,1.,1.,1.,1.,1.,2.);
        if (y ==  4) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,0., 0.,0.,1.,1.,1.,1.,1.,2.);
        if (y ==  3) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,0., 0.,2.,1.,1.,1.,1.,1.,2.);
        if (y ==  2) col = SPRROW(x,0.,1.,2.,1.,1.,1.,1.,1., 2.,2.,1.,1.,1.,2.,1.,2.);
        if (y ==  1) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,2.);
        if (y ==  0) col = SPRROW(x,2.,2.,2.,2.,2.,2.,2.,2., 2.,2.,2.,2.,2.,2.,2.,2.);
        
        if (y < 0 || y > 15) return RGB(107,140,255);
        
        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(231,90,16);
        if (col == 1.0) return RGB(255,165,66);
        if (col == 2.0) return RGB(0,0,0);
        return RGB(107,140,255);
    }

    vec4 sprUsedBlock(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,3.,0.,0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.,0.,3.);
        if (y == 14) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y == 13) col = SPRROW(x,0.,1.,0.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,0.,1.,0.);
        if (y == 12) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y == 11) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y == 10) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  9) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  8) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        
        if (y ==  7) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  6) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  5) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  4) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  3) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  2) col = SPRROW(x,0.,1.,0.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,0.,1.,0.);
        if (y ==  1) col = SPRROW(x,0.,1.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,1.,0.);
        if (y ==  0) col = SPRROW(x,3.,0.,0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.,0.,3.);
        
        if (y < 0 || y > 15) return RGB(107,140,255);
        
        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(0,0,0);
        if (col == 1.0) return RGB(231,90,16);
        return RGB(107,140,255);
    }

    vec4 sprMarioJump(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,0.,0.,0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,2.,2.,2.);
        if (y == 14) col = SPRROW(x,0.,0.,0.,0.,0.,0.,1.,1., 1.,1.,1.,0.,0.,2.,2.,2.);
        if (y == 13) col = SPRROW(x,0.,0.,0.,0.,0.,1.,1.,1., 1.,1.,1.,1.,1.,1.,2.,2.);
        if (y == 12) col = SPRROW(x,0.,0.,0.,0.,0.,3.,3.,3., 2.,2.,3.,2.,0.,3.,3.,3.);
        if (y == 11) col = SPRROW(x,0.,0.,0.,0.,3.,2.,3.,2., 2.,2.,3.,2.,2.,3.,3.,3.);
        if (y == 10) col = SPRROW(x,0.,0.,0.,0.,3.,2.,3.,3., 2.,2.,2.,3.,2.,2.,2.,3.);
        if (y ==  9) col = SPRROW(x,0.,0.,0.,0.,3.,3.,2.,2., 2.,2.,3.,3.,3.,3.,3.,0.);
        if (y ==  8) col = SPRROW(x,0.,0.,0.,0.,0.,0.,2.,2., 2.,2.,2.,2.,2.,3.,0.,0.);
        
        if (y ==  7) col = SPRROW(x,0.,0.,3.,3.,3.,3.,3.,1., 3.,3.,3.,1.,3.,0.,0.,0.);
        if (y ==  6) col = SPRROW(x,0.,3.,3.,3.,3.,3.,3.,3., 1.,3.,3.,3.,1.,0.,0.,3.);
        if (y ==  5) col = SPRROW(x,2.,2.,3.,3.,3.,3.,3.,3., 1.,1.,1.,1.,1.,0.,0.,3.);
        if (y ==  4) col = SPRROW(x,2.,2.,2.,0.,1.,1.,3.,1., 1.,2.,1.,1.,2.,1.,3.,3.);
        if (y ==  3) col = SPRROW(x,0.,2.,0.,3.,1.,1.,1.,1., 1.,1.,1.,1.,1.,1.,3.,3.);
        if (y ==  2) col = SPRROW(x,0.,0.,3.,3.,3.,1.,1.,1., 1.,1.,1.,1.,1.,1.,3.,3.);
        if (y ==  1) col = SPRROW(x,0.,3.,3.,3.,1.,1.,1.,1., 1.,1.,1.,0.,0.,0.,0.,0.);
        if (y ==  0) col = SPRROW(x,0.,3.,0.,0.,1.,1.,1.,1., 0.,0.,0.,0.,0.,0.,0.,0.);
        
        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(0,0,0);
        if (col == 1.0) return RGB(177,52,37);
        if (col == 2.0) return RGB(227,157,37);
        if (col == 3.0) return RGB(106,107,4);
        return RGB(0,0,0);
    }

    vec4 sprMarioWalk3(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,0.,0.,0.,0.,0.,1.,1.,1., 1.,1.,0.,0.,0.,0.,0.,0.);
        if (y == 14) col = SPRROW(x,0.,0.,0.,0.,1.,1.,1.,1., 1.,1.,1.,1.,1.,0.,0.,0.);
        if (y == 13) col = SPRROW(x,0.,0.,0.,0.,3.,3.,3.,2., 2.,3.,2.,0.,0.,0.,0.,0.);
        if (y == 12) col = SPRROW(x,0.,0.,0.,3.,2.,3.,2.,2., 2.,3.,2.,2.,2.,0.,0.,0.);
        if (y == 11) col = SPRROW(x,0.,0.,0.,3.,2.,3.,3.,2., 2.,2.,3.,2.,2.,2.,0.,0.);
        if (y == 10) col = SPRROW(x,0.,0.,0.,3.,3.,2.,2.,2., 2.,3.,3.,3.,3.,0.,0.,0.);
        if (y ==  9) col = SPRROW(x,0.,0.,0.,0.,0.,2.,2.,2., 2.,2.,2.,2.,0.,0.,0.,0.);
        if (y ==  8) col = SPRROW(x,0.,0.,3.,3.,3.,3.,1.,1., 3.,3.,0.,0.,0.,0.,0.,0.);
        
        if (y ==  7) col = SPRROW(x,2.,2.,3.,3.,3.,3.,1.,1., 1.,3.,3.,3.,2.,2.,2.,0.);
        if (y ==  6) col = SPRROW(x,2.,2.,2.,0.,3.,3.,1.,2., 1.,1.,1.,3.,3.,2.,2.,0.);
        if (y ==  5) col = SPRROW(x,2.,2.,0.,0.,1.,1.,1.,1., 1.,1.,1.,0.,0.,3.,0.,0.);
        if (y ==  4) col = SPRROW(x,0.,0.,0.,1.,1.,1.,1.,1., 1.,1.,1.,1.,3.,3.,0.,0.);
        if (y ==  3) col = SPRROW(x,0.,0.,1.,1.,1.,1.,1.,1., 1.,1.,1.,1.,3.,3.,0.,0.);
        if (y ==  2) col = SPRROW(x,0.,3.,3.,1.,1.,1.,0.,0., 0.,1.,1.,1.,3.,3.,0.,0.);
        if (y ==  1) col = SPRROW(x,0.,3.,3.,3.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.,0.,0.);
        if (y ==  0) col = SPRROW(x,0.,0.,3.,3.,3.,0.,0.,0., 0.,0.,0.,0.,0.,0.,0.,0.);

        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(0,0,0);
        if (col == 1.0) return RGB(177,52,37);
        if (col == 2.0) return RGB(227,157,37);
        if (col == 3.0) return RGB(106,107,4);
        return RGB(0,0,0);
    }

    vec4 sprMarioWalk2(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,0.,0.,0.,0.,0.,1.,1.,1., 1.,1.,0.,0.,0.,0.,0.,0.);
        if (y == 14) col = SPRROW(x,0.,0.,0.,0.,1.,1.,1.,1., 1.,1.,1.,1.,1.,0.,0.,0.);
        if (y == 13) col = SPRROW(x,0.,0.,0.,0.,3.,3.,3.,2., 2.,3.,2.,0.,0.,0.,0.,0.);
        if (y == 12) col = SPRROW(x,0.,0.,0.,3.,2.,3.,2.,2., 2.,3.,2.,2.,2.,0.,0.,0.);
        if (y == 11) col = SPRROW(x,0.,0.,0.,3.,2.,3.,3.,2., 2.,2.,3.,2.,2.,2.,0.,0.);
        if (y == 10) col = SPRROW(x,0.,0.,0.,3.,3.,2.,2.,2., 2.,3.,3.,3.,3.,0.,0.,0.);
        if (y ==  9) col = SPRROW(x,0.,0.,0.,0.,0.,2.,2.,2., 2.,2.,2.,2.,0.,0.,0.,0.);
        if (y ==  8) col = SPRROW(x,0.,0.,0.,0.,3.,3.,1.,3., 3.,3.,0.,0.,0.,0.,0.,0.);

        if (y ==  7) col = SPRROW(x,0.,0.,0.,3.,3.,3.,3.,1., 1.,3.,3.,0.,0.,0.,0.,0.);
        if (y ==  6) col = SPRROW(x,0.,0.,0.,3.,3.,3.,1.,1., 2.,1.,1.,2.,0.,0.,0.,0.);
        if (y ==  5) col = SPRROW(x,0.,0.,0.,3.,3.,3.,3.,1., 1.,1.,1.,1.,0.,0.,0.,0.);
        if (y ==  4) col = SPRROW(x,0.,0.,0.,1.,3.,3.,2.,2., 2.,1.,1.,1.,0.,0.,0.,0.);
        if (y ==  3) col = SPRROW(x,0.,0.,0.,0.,1.,3.,2.,2., 1.,1.,1.,0.,0.,0.,0.,0.);
        if (y ==  2) col = SPRROW(x,0.,0.,0.,0.,0.,1.,1.,1., 3.,3.,3.,0.,0.,0.,0.,0.);
        if (y ==  1) col = SPRROW(x,0.,0.,0.,0.,0.,3.,3.,3., 3.,3.,3.,3.,0.,0.,0.,0.);
        if (y ==  0) col = SPRROW(x,0.,0.,0.,0.,0.,3.,3.,3., 3.,0.,0.,0.,0.,0.,0.,0.);

        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(0,0,0);
        if (col == 1.0) return RGB(177,52,37);
        if (col == 2.0) return RGB(227,157,37);
        if (col == 3.0) return RGB(106,107,4);
        return RGB(0,0,0);
    }

    vec4 sprMarioWalk1(int x, int y)
    {
        float col = 0.0;
        if (y == 15) col = SPRROW(x,0.,0.,0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.,0.,0.);
        if (y == 14) col = SPRROW(x,0.,0.,0.,0.,0.,0.,1.,1., 1.,1.,1.,0.,0.,0.,0.,0.);
        if (y == 13) col = SPRROW(x,0.,0.,0.,0.,0.,1.,1.,1., 1.,1.,1.,1.,1.,1.,0.,0.);
        if (y == 12) col = SPRROW(x,0.,0.,0.,0.,0.,3.,3.,3., 2.,2.,3.,2.,0.,0.,0.,0.);
        if (y == 11) col = SPRROW(x,0.,0.,0.,0.,3.,2.,3.,2., 2.,2.,3.,2.,2.,2.,0.,0.);
        if (y == 10) col = SPRROW(x,0.,0.,0.,0.,3.,2.,3.,3., 2.,2.,2.,3.,2.,2.,2.,0.);
        if (y ==  9) col = SPRROW(x,0.,0.,0.,0.,3.,3.,2.,2., 2.,2.,3.,3.,3.,3.,0.,0.);
        if (y ==  8) col = SPRROW(x,0.,0.,0.,0.,0.,0.,2.,2., 2.,2.,2.,2.,2.,0.,0.,0.);

        if (y ==  7) col = SPRROW(x,0.,0.,0.,0.,0.,3.,3.,3., 3.,1.,3.,0.,2.,0.,0.,0.);
        if (y ==  6) col = SPRROW(x,0.,0.,0.,0.,2.,3.,3.,3., 3.,3.,3.,2.,2.,2.,0.,0.);
        if (y ==  5) col = SPRROW(x,0.,0.,0.,2.,2.,1.,3.,3., 3.,3.,3.,2.,2.,0.,0.,0.);
        if (y ==  4) col = SPRROW(x,0.,0.,0.,3.,3.,1.,1.,1., 1.,1.,1.,1.,0.,0.,0.,0.);
        if (y ==  3) col = SPRROW(x,0.,0.,0.,3.,1.,1.,1.,1., 1.,1.,1.,1.,0.,0.,0.,0.);
        if (y ==  2) col = SPRROW(x,0.,0.,3.,3.,1.,1.,1.,0., 1.,1.,1.,0.,0.,0.,0.,0.);
        if (y ==  1) col = SPRROW(x,0.,0.,3.,0.,0.,0.,0.,3., 3.,3.,0.,0.,0.,0.,0.,0.);
        if (y ==  0) col = SPRROW(x,0.,0.,0.,0.,0.,0.,0.,3., 3.,3.,3.,0.,0.,0.,0.,0.);

        col = SELECT(mod(float(x),8.0),col);
        if (col == 0.0) return RGB(0,0,0);
        if (col == 1.0) return RGB(177,52,37);
        if (col == 2.0) return RGB(227,157,37);
        if (col == 3.0) return RGB(106,107,4);
        return RGB(0,0,0);
    }

    vec4 getTile(int t, int x, int y)
    {
        if (t == 0) return RGB(107,140,255);
        if (t == 1) return sprGround(x,y);
        if (t == 2) return sprQuestionBlock(x,y);
        if (t == 3) return sprUsedBlock(x,y);
        
        return RGB(107,140,255);
    }

    int getSection(int s, int x, int y)
    {
        float col = 0.0;
        if (s == 0) {
            if (y == 6) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 5) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 4) col = SECROW(x,0.,0.,3.,3.,3.,0.,0.,0.);
            if (y == 3) col = SECROW(x,0.,0.,2.,2.,2.,0.,0.,0.);
            if (y == 2) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 1) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y <= 0) col = SECROW(x,1.,1.,1.,1.,1.,1.,1.,1.);
        }
        if (s == 1) {
            if (y == 6) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 5) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 4) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 3) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 2) col = SECROW(x,0.,0.,0.,0.,0.,1.,0.,0.);
            if (y == 1) col = SECROW(x,0.,0.,0.,1.,1.,1.,0.,0.);
            if (y <= 0) col = SECROW(x,1.,1.,1.,1.,1.,1.,1.,1.);
        }
        if (s == 2) {
            if (y == 6) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 5) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 4) col = SECROW(x,0.,0.,3.,0.,0.,3.,0.,0.);
            if (y == 3) col = SECROW(x,0.,0.,2.,0.,0.,2.,0.,0.);
            if (y == 2) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 1) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y <= 0) col = SECROW(x,1.,1.,1.,1.,1.,1.,1.,1.);
        }
        if (s == 3) {
            if (y == 6) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 5) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 4) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 3) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 2) col = SECROW(x,0.,0.,0.,1.,1.,0.,0.,0.);
            if (y == 1) col = SECROW(x,0.,0.,0.,1.,1.,1.,0.,0.);
            if (y <= 0) col = SECROW(x,1.,1.,1.,1.,1.,1.,1.,1.);
        }
        if (s == 4) {
            if (y == 6) col = SECROW(x,0.,0.,0.,0.,3.,0.,0.,0.);
            if (y == 5) col = SECROW(x,0.,0.,0.,0.,2.,0.,0.,0.);
            if (y == 4) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 3) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 2) col = SECROW(x,0.,0.,0.,1.,1.,1.,0.,0.);
            if (y == 1) col = SECROW(x,0.,0.,0.,1.,1.,1.,0.,0.);
            if (y <= 0) col = SECROW(x,1.,1.,1.,1.,1.,1.,1.,1.);
        }
        if (s == 5) {
            if (y == 6) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 5) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 4) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 3) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 2) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y == 1) col = SECROW(x,0.,0.,0.,0.,0.,0.,0.,0.);
            if (y <= 0) col = SECROW(x,1.,1.,1.,0.,0.,1.,1.,1.);
        }
        
        
        
        return int(SELECTSEC(mod(float(x),4.0),col));
    }

    int getBlock(int x, int y)
    {
    #ifdef TOTALLY_RANDOM_LEVEL
        int height = 1 + int(rand(vec2(int(float(x) / 3.0),2.3)) * 3.0);
        return (y < height ? 1 : 0);
    #else
        if (y > 6) return 0;
        
        int section = int(rand(vec2(int(float(x) / 8.0),3.0)) * 6.0);
        int sectionX = int(mod(float(x), 8.0));
        
        return getSection(section,sectionX,y - int(rand(vec2(section,2.0)) * 0.0));
    #endif
    }

    bool isSolid(int b)
    {
        return (b != 0);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        const float gameSpeed = 60.0;
        
        // Get the current game pixel
        // (Each game pixel is two screen pixels)
        //  (or four, if the screen is larger)
        float x = fragCoord.x / 2.0;
        float y = fragCoord.y / 2.0;
        if (iResolution.y >= 640.0) {
            x /= 2.0;
            y /= 2.0;
        }
        if (iResolution.y < 200.0) {
            x *= 2.0;
            y *= 2.0;
        }
        
        // Just move the screen up for half a block's size
        y -= 8.0;

        // Get the grid index of the block at this pixel,
        // and of the block at the screen's leftmost position
        int firstBlockX = int((iTime * gameSpeed) / 16.0);
        int blockX = int((x + iTime * gameSpeed) / 16.0);
        int blockY = int(y / 16.0);
        
        // Ask for the block ID that exists in the current position
        int block = getBlock(blockX,blockY);
        
        // Get the fractional position inside current block
        int subx = int(mod((x + iTime * gameSpeed),16.0));
        int suby = int(mod(y,16.0));
        
        // Animate block if it's a Question Block
        if (block == 2) {
            if (blockX - firstBlockX == 5) {
                suby -= int(max(0.0,(sin(mod((iTime * gameSpeed / 16.0),1.0) * 3.141592 * 1.5) * 8.0)));
            }
            
            if ((floor((x + iTime * gameSpeed) / 16.0) - (iTime * gameSpeed) / 16.0) < 4.25) block = 3;
        // Animate block if it's on top of a Question Block
        } else if (block == 3) {
            block = 2;
            suby += 16;
            if (blockX - firstBlockX == 5) {
                suby -= int(max(0.0,(sin(mod((iTime * gameSpeed / 16.0),1.0) * 3.141592 * 1.5) * 8.0)));
            }
        }
        // Get the final color for this pixel
        // (Mario can override this later on)
        fragColor = getTile(block,subx,suby);
        
        
        // If this is the column where Mario stops simulating...
        // (it's the only column he can appear in)
        if (x >= endX && x < endX + 16.0) {
            
            // Screen position in pixels:
            // Every block is 16 pixels wide
            float screenX = iTime * gameSpeed;
            
            // Mario's starting position and speed
            float marioX = screenX + startX;
            float marioY = 16.0;
            float marioXSpd = 4.0;
            float marioYSpd = 0.0;
            
            // Find out the first empty block in this column,
            // starting from the bottom, as to put Mario on top of it
            for(int i = 1; i < 4; i++) {
                if (!isSolid(getBlock(int(marioX / 16.0), i))) {
                    marioY = float(i) * 16.0;
                    break;
                }
            }
            
            // Number of steps to simulate;
            // We'll simulate at 15 FPS and interpolate later,
            // hence the division by 4.0
            // (Mario should actually be walking 1 pixel every 1/60th of a second,
            //  but he'll be walking 4 pixels every 1/15th)
            const int simSteps = int((endX - startX) / 4.0);
            
            // Previous position, as to interpolate later, for high frame rates
            float lastX = 0.0;
            float lastY = 0.0;
            
            // Start simulating
            bool onGround = false;
            for(int sim = 0; sim < simSteps; sim++) {
                // Store the previous position
                lastX = marioX;
                lastY = marioY;
                
                // If Mario is inside a block, move him up
                // (This happens only at the start of the simulation,
                //  sometimes because he is heads-up with a wall and
                //  cannot make a jump properly)
                onGround = false;
                if (isSolid(getBlock(int(marioX / 16.0) + 1, int(marioY / 16.0)))) {
                    marioY = (floor(marioY / 16.0) * 16.0) + 16.0;
                }
                
                // Next, pretty standard platforming code
                
                // Apply gravity and move in the Y-axis
                marioYSpd -= 2.5;
                marioY += marioYSpd;
                
                // If he is going up,
                // and if there is a block above him,
                // align him with the grid (as to avoid getting inside the block),
                // and invert his YSpeed, as to fall quickly (because he bounced his head)
                if (marioYSpd > 0.0) {
                    if (isSolid(getBlock(int(floor((marioX + 12.0) / 16.0)), int(floor((marioY + 15.9) / 16.0))))) {
                        marioYSpd *= -0.5;
                        marioY = (floor(marioY / 16.0) * 16.0);
                    }
                }
                
                // If he is going down,
                // and if there is a block beneath him,
                // align him with the grid (as to land properly on top of the block),
                // and mark him as onGround (to be able to perform a jump)
                if (marioYSpd < 0.0) {
                    if (isSolid(getBlock(int(floor((marioX) / 16.0)), int(floor(marioY / 16.0)))) ||
                        isSolid(getBlock(int(floor((marioX + 15.9) / 16.0)), int(floor(marioY / 16.0))))) {
                        marioYSpd = 0.0;
                        marioY = (floor(marioY / 16.0) * 16.0) + 16.0;
                        onGround = true;
                    }
                }
                
                // Finally, move him in the X-axis
                // I assume here he'll never hit a block horizontally
                marioX += marioXSpd;
                
                // Now, if he's onGround,
                // and if there are blocks in front of him,
                // or if there is a pit right next to him,
                // set his YSpeed to jump
                if (onGround) {
                    if (!isSolid(getBlock(int((marioX) / 16.0) + 1,0))) {
                        marioYSpd = 15.5;
                    } else if (isSolid(getBlock(int((marioX + 36.0) / 16.0), int((marioY + 24.0) / 16.0)))) {
                        marioYSpd = 15.5;
                    } else if (isSolid(getBlock(int((marioX) / 16.0) + 2, int((marioY + 8.0) / 16.0)))) {
                        marioYSpd = 12.5;
                    } else if (getBlock(int((marioX) / 16.0) + 1, int((marioY + 8.0) / 16.0) + 2) == 2) {
                        marioYSpd = 15.5;
                    }
                    
                }
            }
            
            // Interpolate Y-pos for smooth high-frame-rate movement
            marioY = mix(lastY,marioY,mod(iTime * 15.0,1.0)) - 1.0;
            
            // Finally, if he appears at this row, fetch a pixel from his sprites
            if (y >= marioY && y < marioY + 16.0) {
                vec4 spr = vec4(0,0,0,0);
                if (onGround) {
                    // Which frame?
                    int f = int(mod(iTime * 10.0, 3.0));
                    if (f == 0) spr = sprMarioWalk1(int(x - (marioX - screenX)),int(y - marioY));
                    if (f == 1) spr = sprMarioWalk2(int(x - (marioX - screenX)),int(y - marioY));
                    if (f == 2) spr = sprMarioWalk3(int(x - (marioX - screenX)),int(y - marioY));
                } else {
                    spr = sprMarioJump(int(x - (marioX - screenX)),int(y - marioY));
                }
                // Transparency check
                if (spr.x != 0.0) fragColor = spr;
            }
        }
    }
    """

    src_fl = """
    ///////////////////Fractal Flythrough
    /*
        Fractal Flythrough
        ------------------

        Moving a camera through a fractal object. It's a work in progress.

        I was looking at one of Dr2's shaders that involved moving a camera through a set of way points (set
        out on the XZ plane), and thought it'd be cool to do a similar 3D version. The idea was to create a
        repetitive kind of fractal object, give the open space nodes a set random direction, create some 
        spline points, then run a smooth camera through them. Simple... right? It always seems simple in my
        head, but gets progressively harder when I try it in a shader. :)

        I've run into that classic up-vector, camera flipping problem... At least, I think that's the problem? 
        Anyway, I'm hoping the solution is simple, and that someone reading this will be able to point me in 
        the right direction.

        For now, I've set up a set of 16 random looping points that the camera seems reasonably comfortable 
        with. Just for the record, the general setup works nicely, until the camera loops back on itself in 
        the YZ plane. I'm guessing that increasing the number of way points may eradicate some of the
        intermittent camera spinning, but I figured I'd leave things alone and treat it as a feature. :)

        By the way, I was thankful to have Otavio Good's spline setup in his "Alien Beacon" shader as a 
        reference. On a side note, that particular shader is one of my all time favorites on this site.

        The rendering materials are slightly inspired by the Steampunk genre. Timber, granite, brass, etc. 
        It needs spinning turbines, gears, rivots, and so forth, but that stuff's expensive. Maybe later. 
        Tambako Jaguar did a really cool shader in the Steampunk aesthetic. The link is below.

        Besides camera path, there's a whole bunch of improvements I'd like to make to this. I've relied on
        occlusion to mask the fact that there are no shadows. I'm hoping to free up some cycles, so I can put
        them back in. I'd also like to add extra detail, but that also slows things down. As for the comments,
        they're very rushed, but I'll tidy those up as well.

        References:

        Alien Beacon - Otavio Good
        https://www.shadertoy.com/view/ld2SzK

        Steampunk Turbine - TambakoJaguar
        https://www.shadertoy.com/view/lsd3zf

        // The main inspiration for this shader.
        Mandelmaze in Daylight - dr2
        https://www.shadertoy.com/view/MdVGRc

    */

    const float FAR = 50.0; // Far plane.

    // Used to identify individual scene objects. In this case, there are only three: The metal framework, the gold
    // and the timber.
    float objID = 0.; // Wood = 1., Metal = 2., Gold = 3..

    // Simple hash function.
    float hash( float n ){ return fract(cos(n)*45758.5453); }

    // Tri-Planar blending function. Based on an old Nvidia writeup:
    // GPU Gems 3 - Ryan Geiss: https://developer.nvidia.com/gpugems/GPUGems3/gpugems3_ch01.html
    vec3 tex3D(sampler2D t, in vec3 p, in vec3 n ){

        n = max(abs(n), 0.001);
        n /= dot(n, vec3(1));
        vec3 tx = texture(t, p.yz).xyz;
        vec3 ty = texture(t, p.zx).xyz;
        vec3 tz = texture(t, p.xy).xyz;

        // Textures are stored in sRGB (I think), so you have to convert them to linear space 
        // (squaring is a rough approximation) prior to working with them... or something like that. :)
        // Once the final color value is gamma corrected, you should see correct looking colors.
        return (tx*tx*n.x + ty*ty*n.y + tz*tz*n.z);
    }

    // Common formula for rounded squares, for all intended purposes.
    float lengthN(in vec2 p, in float n){ p = pow(abs(p), vec2(n)); return pow(p.x + p.y, 1.0/n); }


    // The camera path: There are a few spline setups on Shadertoy, but this one is a slight variation of
    // Otavio Good's spline setup in his "Alien Beacon" shader: https://www.shadertoy.com/view/ld2SzK
    //
    // Spline point markers ("cp" for camera point). The camera visits each point in succession, then loops
    // back to the first point, when complete, in order to repeat the process. In case it isn't obvious, each 
    // point represents an open space juncture in the object that links to the previous and next point.
    // Of course, running a camera in a straight line between points wouldn't produce a smooth camera effect, 
    // so we apply the Catmull-Rom equation to the line segment.
    vec3 cp[16];

    void setCamPath(){
        
        // The larger fractal object has nodes in a 4x4x4 grid.
        // The smaller one in a 2x2x2 grid. The following points
        // map a path to various open areas throughout the object.
        const float sl = 2.*.96;
        const float bl = 4.*.96;
        
        cp[0] = vec3(0, 0, 0);
        cp[1] = vec3(0, 0, bl);
        cp[2] = vec3(sl, 0, bl);
        cp[3] = vec3(sl, 0, sl);
        cp[4] = vec3(sl, sl, sl);   
        cp[5] = vec3(-sl, sl, sl);  
        cp[6] = vec3(-sl, 0, sl);
        cp[7] = vec3(-sl, 0, 0);
        
        cp[8] = vec3(0, 0, 0);  
        cp[9] = vec3(0, 0, -bl);
        cp[10] = vec3(0, bl, -bl);  
        cp[11] = vec3(-sl, bl, -bl);
        cp[12] = vec3(-sl, 0, -bl);
        cp[13] = vec3(-sl, 0, 0);
        cp[14] = vec3(-sl, -sl, 0);
        cp[15] = vec3(0, -sl, 0); 
        
        // Tighening the radius a little, so that the camera doesn't hit the walls.
        // I should probably hardcode this into the above... Done.
        //for(int i=0; i<16; i++) cp[i] *= .96;
        
    }

    // Standard Catmull-Rom equation. The equation takes in the line segment end points (p1 and p2), the
    // points on either side (p0 and p3), the current fractional distance (t) along the segment, then
    // returns the the smooth (cubic interpolated) position. The end result is a smooth transition 
    // between points... Look up a diagram on the internet. That should make it clearer.
    vec3 Catmull(vec3 p0, vec3 p1, vec3 p2, vec3 p3, float t){

        return (((-p0 + p1*3. - p2*3. + p3)*t*t*t + (p0*2. - p1*5. + p2*4. - p3)*t*t + (-p0 + p2)*t + p1*2.)*.5);
    }

    // Camera path. Determine the segment number (segNum), and how far - timewise - we are along it (segTime).
    // Feed the segment, the appropriate adjoining segments, and the segment time into the Catmull-Rom
    // equation to produce a camera position. The process is pretty simple, once you get the hang of it.
    vec3 camPath(float t){

        const int aNum = 16;
        
        t = fract(t/float(aNum))*float(aNum);   // Repeat every 16 time units.

        // Segment number. Range: [0, 15], in this case.
        float segNum = floor(t);
        // Segment portion. Analogous to how far we are alone the individual line segment. Range: [0, 1].
        float segTime = t - segNum; 

        if (segNum == 0.) return Catmull(cp[aNum-1], cp[0], cp[1], cp[2], segTime); 
        
        for(int i=1; i<aNum-2; i++){
            if (segNum == float(i)) return Catmull(cp[i-1], cp[i], cp[i+1], cp[i+2], segTime); 
        }

        if (segNum == float(aNum-2)) return Catmull(cp[aNum-3], cp[aNum-2], cp[aNum-1], cp[0], segTime); 
        if (segNum == float(aNum-1)) return Catmull(cp[aNum-2], cp[aNum-1], cp[0], cp[1], segTime);

        return vec3(0);
    }

    // Smooth minimum function. There are countless articles, but IQ explains it best here:
    // https://iquilezles.org/articles/smin
    float sminP( float a, float b, float s ){

        float h = clamp( 0.5+0.5*(b-a)/s, 0.0, 1.0 );
        return mix( b, a, h ) - s*h*(1.0-h);
    }

    // Creating the scene geometry.
    //
    // There are two intertwined fractal objects. One is a gold and timber lattice, spread out in a 4x4x4
    // grid. The second is some metallic tubing spread out over a 2x2x2 grid. Each are created by combining
    // repeat objects with various operations. All of it is pretty standard.
    //
    // The code is a little fused together, in order to save some cycles, but if you're interested in the 
    // process, I have a "Menger Tunnel" example that's a little easier to decipher.
    float map(in vec3 q){
    ///////////

        // The grey section. I have another Menger example, if you'd like to look into that more closely.
        // Layer one.
        vec3 p = abs(fract(q/4.)*4. - 2.);
        float tube = min(max(p.x, p.y), min(max(p.y, p.z), max(p.x, p.z))) - 4./3. - .015;// + .05;

        // Layer two.
        p = abs(fract(q/2.)*2. - 1.);
        //d = max(d, min(max(p.x, p.y), min(max(p.y, p.z), max(p.x, p.z))) - s/3.);// + .025
        tube = max(tube, sminP(max(p.x, p.y), sminP(max(p.y, p.z), max(p.x, p.z), .05), .05) - 2./3.);// + .025

    ///////
        // The gold and timber paneling.
        //
        // A bit of paneling, using a combination of repeat objects. We're doing it here in layer two, just
        // to save an extra "fract" call. Very messy, but saves a few cycles... maybe.

        //float panel = sminP(length(p.xy),sminP(length(p.yz),length(p.xz), 0.25), 0.125)-0.45; // EQN 1
        //float panel = sqrt(min(dot(p.xy, p.xy),min(dot(p.yz, p.yz),dot(p.xz, p.xz))))-0.5; // EQN 2
        //float panel = min(max(p.x, p.y),min(max(p.y, p.z),max(p.x, p.z)))-0.5; // EQN 3
        float panel = sminP(max(p.x, p.y),sminP(max(p.y, p.z),max(p.x, p.z), .125), .125)-0.5; // EQN 3

        // Gold strip. Probably not the best way to do this, but it gets the job done.
        // Identifying the gold strip region, then edging it out a little... for whatever reason. :)
        float strip = step(p.x, .75)*step(p.y, .75)*step(p.z, .75);
        panel -= (strip)*.025;     
        
        // Timber bulge. Just another weird variation.
        //float bulge = (max(max(p.x, p.y), p.z) - .55);//length(p)-1.;//
        //panel -= bulge*(1.-step(p.x, .75)*step(p.y, .75)*step(p.z, .75))*bulge*.25;    
        
        // Repeat field entity two, which is just an abstract object repeated every half unit. 
        p = abs(fract(q*2.)*.5 - .25);
        float pan2 = min(p.x, min(p.y,p.z))-.05;

        // Combining the two entities above.
        panel = max(abs(panel), abs(pan2)) - .0425;
    /////////

        // Layer three. 3D space is divided by three.
        p = abs(fract(q*1.5)/1.5 - 1./3.);
        tube = max(tube, min(max(p.x, p.y), min(max(p.y, p.z), max(p.x, p.z))) - 2./9. + .025); // + .025 


        // Layer three. 3D space is divided by two, instead of three, to give some variance.
        p = abs(fract(q*3.)/3. - 1./6.);
        tube = max(tube, min(max(p.x, p.y), min(max(p.y, p.z), max(p.x, p.z))) - 1./9. - .035); //- .025 

        // Object ID: Equivalent to: if(tube<panel)objID=2; else objID = 1.; //etc.
        //
        // By the way, if you need to identify multiple objects, you're better off doing it in a seperate pass, 
        // after the raymarching function. Having multiple "if" statements in a distance field equation can 
        // slow things down considerably.
            
        //objID = 2. - step(tube, panel) + step(panel, tube)*(strip);
        objID = 1.+ step(tube, panel) + step(panel, tube)*(strip)*2.;
        //objID = 1. + step(panel, tube)*(strip) + step(tube, panel)*2.;

        return min(panel, tube);
    }

    float trace(in vec3 ro, in vec3 rd){

        float t = 0., h;
        for(int i = 0; i < 92; i++){
        
            h = map(ro+rd*t);
            // Note the "t*b + a" addition. Basically, we're putting less emphasis on accuracy, as
            // "t" increases. It's a cheap trick that works in most situations... Not all, though.
            if(abs(h)<.001*(t*.25 + 1.) || t>FAR) break; // Alternative: 0.001*max(t*.25, 1.)
            t += h*.8;
            
        }
        return t;
    }

    // The reflections are pretty subtle, so not much effort is being put into them. Only 16 iterations.
    float refTrace(vec3 ro, vec3 rd){

        float t = 0.;
        for(int i=0; i<16; i++){
            float d = map(ro + rd*t);
            if (d < .0025*(t*.25 + 1.) || t>FAR) break;
            t += d;
        } 
        return t;
    }

    /*
    // Tetrahedral normal, to save a couple of "map" calls. Courtesy of IQ.
    vec3 calcNormal(in vec3 p){

        // Note the slightly increased sampling distance, to alleviate artifacts due to hit point inaccuracies.
        vec2 e = vec2(0.0025, -0.0025); 
        return normalize(e.xyy * map(p + e.xyy) + e.yyx * map(p + e.yyx) + e.yxy * map(p + e.yxy) + e.xxx * map(p + e.xxx));
    }
    */

    // Standard normal function. It's not as fast as the tetrahedral calculation, but more symmetrical. Due to 
    // the intricacies of this particular scene, it's kind of needed to reduce jagged effects.
    vec3 calcNormal(in vec3 p) {
        const vec2 e = vec2(0.005, 0);
        return normalize(vec3(map(p + e.xyy) - map(p - e.xyy), map(p + e.yxy) - map(p - e.yxy), map(p + e.yyx) - map(p - e.yyx)));
    }

    // I keep a collection of occlusion routines... OK, that sounded really nerdy. :)
    // Anyway, I like this one. I'm assuming it's based on IQ's original.
    float calcAO(in vec3 pos, in vec3 nor)
    {
        float sca = 2.0, occ = 0.0;
        for( int i=0; i<5; i++ ){

            float hr = 0.01 + float(i)*0.5/4.0;
            float dd = map(nor * hr + pos);
            occ += (hr - dd)*sca;
            sca *= 0.7;
        }
        return clamp( 1.0 - occ, 0.0, 1.0 );
    }

    // Texture bump mapping. Four tri-planar lookups, or 12 texture lookups in total. I tried to 
    // make it as concise as possible. Whether that translates to speed, or not, I couldn't say.
    vec3 texBump( sampler2D tx, in vec3 p, in vec3 n, float bf){

        const vec2 e = vec2(0.001, 0);

        // Three gradient vectors rolled into a matrix, constructed with offset greyscale texture values.
        mat3 m = mat3( tex3D(tx, p - e.xyy, n), tex3D(tx, p - e.yxy, n), tex3D(tx, p - e.yyx, n));

        vec3 g = vec3(0.299, 0.587, 0.114)*m; // Converting to greyscale.
        g = (g - dot(tex3D(tx,  p , n), vec3(0.299, 0.587, 0.114)) )/e.x; g -= n*dot(n, g);

        return normalize( n + g*bf ); // Bumped normal. "bf" - bump factor.
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ){

        // Screen coordinates.
        vec2 u = (fragCoord - iResolution.xy*0.5)/iResolution.y;

        float speed = iTime*0.1 + 8.;

        // Initiate the camera path spline points. Kind of wasteful not making this global, but I wanted
        // it self contained... for better or worse. I'm not really sure what the GPU would prefer.
        setCamPath();

        // Camera Setup.
        vec3 ro = camPath(speed); // Camera position, doubling as the ray origin.
        vec3 lk = camPath(speed + .5);  // "Look At" position.
        vec3 lp = camPath(speed + .5) + vec3(0, .25, 0); // Light position, somewhere near the moving camera.

        // Using the above to produce the unit ray-direction vector.
        float FOV = 1.57; // FOV - Field of view.
        vec3 fwd = normalize(lk-ro);
        vec3 rgt = normalize(vec3(fwd.z, 0, -fwd.x));
        vec3 up = (cross(fwd, rgt));

            // Unit direction ray.
        vec3 rd = normalize(fwd + FOV*(u.x*rgt + u.y*up));

        // Raymarch the scene.
        float t = trace(ro, rd);

        // Initialize the scene color.
        vec3 col = vec3(0);

        // Scene hit, so color the pixel. Technically, the object should always be hit, so it's tempting to
        // remove this entire branch... but I'll leave it, for now.
        if(t<FAR){

            // This looks a little messy and haphazard, but it's really just some basic lighting, and application
            // of the following material properties: Wood = 1., Metal = 2., Gold = 3..

            float ts = 1.;  // Texture scale.

            // Global object ID. It needs to be saved just after the raymarching equation, since other "map" calls,
            // like normal calculations will give incorrect results. Found that out the hard way. :)
            float saveObjID = objID; 

            vec3 pos = ro + rd*t; // Scene postion.
            vec3 nor = calcNormal(pos); // Normal.
            vec3 sNor = nor;

            // Apply some subtle texture bump mapping to the panels and the metal tubing.
            nor = texBump(iChannel0, pos*ts, nor, 0.002); // + step(saveObjID, 1.5)*0.002

            // Reflected ray. Note that the normal is only half bumped. It's fake, but it helps
            // taking some of the warping effect off of the reflections.
            vec3 ref = reflect(rd, normalize(sNor*.5 + nor*.5)); 

            col = tex3D(iChannel0, pos*ts, nor); // Texture pixel at the scene postion.

            vec3  li = lp - pos; // Point light.
            float lDist = max(length(li), .001); // Surface to light distance.
            float atten = 1./(1.0 + lDist*0.125 + lDist*lDist*.05); // Light attenuation.
            li /= lDist; // Normalizing the point light vector.

            float occ = calcAO( pos, nor ); // Occlusion.

            float dif = clamp(dot(nor, li), 0.0, 1.0); // Diffuse.
            dif = pow(dif, 4.)*2.;
            float spe = pow(max(dot(reflect(-li, nor), -rd), 0.), 8.); // Object specular.
            float spe2 = spe*spe; // Global specular.

            float refl = .35; // Reflection coefficient. Different for different materials.

            // Reflection color. Mostly fake.
            // Cheap reflection: Not entirely accurate, but the reflections are pretty subtle, so not much 
            // effort is being put in.
            float rt = refTrace(pos + ref*0.1, ref); // Raymarch from "sp" in the reflected direction.
            float rSaveObjID = objID; // IDs change with reflection. Learned that the hard way. :)
            vec3 rsp = pos + ref*rt; // Reflected surface hit point.
            vec3 rsn = calcNormal(rsp); // Normal at the reflected surface. Too costly to bump reflections.
            vec3 rCol = tex3D(iChannel0, rsp*ts, rsn); // Texel at "rsp."
            vec3 rLi = lp-rsp;
            float rlDist = max(length(rLi), 0.001);
            rLi /= rlDist;
            float rDiff = max(dot(rsn, rLi), 0.); // Diffuse light at "rsp."
            rDiff = pow(rDiff, 4.)*2.;
            float rAtten = 1./(1. + rlDist*0.125 + rlDist*rlDist*.05);

            if(rSaveObjID>1.5 && rSaveObjID<2.5){
                rCol = vec3(1)*dot(rCol, vec3(.299, .587, .114))*.7 + rCol*.15;//*.7+.2
                //rDiff *= 1.35;
            }
            if(rSaveObjID>2.5){
                 //float rc = dot(rCol, vec3(.299, .587, .114));
                 vec3 rFire = pow(vec3(1.5, 1, 1)*rCol, vec3(8, 2, 1.5));//*.5+rc*.5;
                 rCol = min(mix(vec3(1.5, .9, .375), vec3(.75, .375, .3), rFire), 2.)*.5 + rCol;         
            }

            rCol *= (rDiff + .35)*rAtten; // Reflected color. Not accurate, but close enough.         

            // Grey metal inner tubing.
            if(saveObjID>1.5 && saveObjID<2.5){ 

                // Grey out the limestone wall color.
                col = vec3(1)*dot(col, vec3(.299, .587, .114))*.7 + col*.15;

                refl = .5;
                //dif *= 1.35;
                //spe2 *= 1.35;
            }

            // Gold trimming properties. More effort should probably be put in here.
            // I could just write "saveObjID == 3.," but I get a little paranoid where floats are concerned. :)
            if(saveObjID>2.5){

                // For the screen image, we're interested in the offset height and depth positions. Ie: pOffs.zy.
                // Pixelized dot pattern shade.
                //float c = dot(col, vec3(.299, .587, .114));

                vec3 fire = pow(vec3(1.5, 1, 1)*col, vec3(8, 2, 1.5));//*.5+c*.5;
                col = min(mix(vec3(1, .9, .375), vec3(.75, .375, .3), fire), 2.)*.5 + col;//
                refl = .65;
                //dif *= 1.5;
                //spe2 *= 1.5;
            }

            // Combining everything together to produce the scene color.
            col = col*(dif + .35  + vec3(.35, .45, .5)*spe) + vec3(.7, .9, 1)*spe2 + rCol*refl;
            col *= occ*atten; // Applying occlusion.
        }

        // Applying some very slight fog in the distance. This is technically an inside scene...
        // Or is it underground... Who cares, it's just a shader. :)
        col = mix(min(col, 1.), vec3(0), 1.-exp(-t*t/FAR/FAR*20.));//smoothstep(0., FAR-20., t)
        //col = mix(min(col, 1.), vec3(0), smoothstep(0., FAR-35., t));//smoothstep(0., FAR-20., t)

        // Done.
        fragColor = vec4(sqrt(max(col, 0.)), 1.0);
    }
    """

    src_bc = """
    ///////////////////
    //Calculate the squared length of a vector
    float length2(vec2 p){
        return dot(p,p);
    }

    //Generate some noise to scatter points.
    float noise(vec2 p){
        return fract(sin(fract(sin(p.x) * (43.13311)) + p.y) * 31.0011);
    }

    float worley(vec2 p) {
        //Set our distance to infinity
        float d = 1e30;
        //For the 9 surrounding grid points
        for (int xo = -1; xo <= 1; ++xo) {
            for (int yo = -1; yo <= 1; ++yo) {
                //Floor our vec2 and add an offset to create our point
                vec2 tp = floor(p) + vec2(xo, yo);
                //Calculate the minimum distance for this grid point
                //Mix in the noise value too!
                d = min(d, length2(p - tp - noise(tp)));
            }
        }
        return 3.0*exp(-4.0*abs(2.5*d - 1.0));
    }

    float fworley(vec2 p) {
        //Stack noise layers 
        return sqrt(sqrt(sqrt(
            worley(p*5.0 + 0.05*iTime) *
            sqrt(worley(p * 50.0 + 0.12 + -0.1*iTime)) *
            sqrt(sqrt(worley(p * -10.0 + 0.03*iTime))))));
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        //Calculate an intensity
        float t = fworley(uv * iResolution.xy / 1500.0);
        //Add some gradient
        t*=exp(-length2(abs(0.7*uv - 1.0)));    
        //Make it blue!
        fragColor = vec4(t * vec3(0.1, 1.1*t, pow(t, 0.5-t)), 1.0);
    }
    """

    src_em = """
    /////////////////// Smiley
    // "Smiley Tutorial" by Martijn Steinrucken aka BigWings - 2017
    // License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
    // Email:countfrolic@gmail.com Twitter:@The_ArtOfCode
    //
    // This Smiley is part of my ShaderToy Tutorial series on YouTube:
    // Part 1 - Creating the Smiley - https://www.youtube.com/watch?v=ZlNnrpM0TRg
    // Part 2 - Animating the Smiley - https://www.youtube.com/watch?v=vlD_KOrzGDc&t=83s

    #define S(a, b, t) smoothstep(a, b, t)
    #define B(a, b, blur, t) S(a-blur, a+blur, t)*S(b+blur, b-blur, t)
    #define sat(x) clamp(x, 0., 1.)

    float remap01(float a, float b, float t) {
        return sat((t-a)/(b-a));
    }

    float remap(float a, float b, float c, float d, float t) {
        return sat((t-a)/(b-a)) * (d-c) + c;
    }

    vec2 within(vec2 uv, vec4 rect) {
        return (uv-rect.xy)/(rect.zw-rect.xy);
    }

    vec4 Brow(vec2 uv, float smile) {
        float offs = mix(.2, 0., smile);
        uv.y += offs;
        
        float y = uv.y;
        uv.y += uv.x*mix(.5, .8, smile)-mix(.1, .3, smile);
        uv.x -= mix(.0, .1, smile);
        uv -= .5;
        
        vec4 col = vec4(0.);
        
        float blur = .1;
        
        float d1 = length(uv);
        float s1 = S(.45, .45-blur, d1);
        float d2 = length(uv-vec2(.1, -.2)*.7);
        float s2 = S(.5, .5-blur, d2);
        
        float browMask = sat(s1-s2);
        
        float colMask = remap01(.7, .8, y)*.75;
        colMask *= S(.6, .9, browMask);
        colMask *= smile;
        vec4 browCol = mix(vec4(.4, .2, .2, 1.), vec4(1., .75, .5, 1.), colMask); 
       
        uv.y += .15-offs*.5;
        blur += mix(.0, .1, smile);
        d1 = length(uv);
        s1 = S(.45, .45-blur, d1);
        d2 = length(uv-vec2(.1, -.2)*.7);
        s2 = S(.5, .5-blur, d2);
        float shadowMask = sat(s1-s2);
        
        col = mix(col, vec4(0.,0.,0.,1.), S(.0, 1., shadowMask)*.5);
        
        col = mix(col, browCol, S(.2, .4, browMask));
        
        return col;
    }

    vec4 Eye(vec2 uv, float side, vec2 m, float smile) {
        uv -= .5;
        uv.x *= side;
        
        float d = length(uv);
        vec4 irisCol = vec4(.3, .5, 1., 1.);
        vec4 col = mix(vec4(1.), irisCol, S(.1, .7, d)*.5);     // gradient in eye-white
        col.a = S(.5, .48, d);                                  // eye mask
        
        col.rgb *= 1. - S(.45, .5, d)*.5*sat(-uv.y-uv.x*side);  // eye shadow
        
        d = length(uv-m*.4);                                    // offset iris pos to look at mouse cursor
        col.rgb = mix(col.rgb, vec3(0.), S(.3, .28, d));        // iris outline
        
        irisCol.rgb *= 1. + S(.3, .05, d);                      // iris lighter in center
        float irisMask = S(.28, .25, d);
        col.rgb = mix(col.rgb, irisCol.rgb, irisMask);          // blend in iris
        
        d = length(uv-m*.45);                                   // offset pupile to look at mouse cursor
        
        float pupilSize = mix(.4, .16, smile);
        float pupilMask = S(pupilSize, pupilSize*.85, d);
        pupilMask *= irisMask;
        col.rgb = mix(col.rgb, vec3(0.), pupilMask);        // blend in pupil
        
        float t = iTime*3.;
        vec2 offs = vec2(sin(t+uv.y*25.), sin(t+uv.x*25.));
        offs *= .01*(1.-smile);
        
        uv += offs;
        float highlight = S(.1, .09, length(uv-vec2(-.15, .15)));
        highlight += S(.07, .05, length(uv+vec2(-.08, .08)));
        col.rgb = mix(col.rgb, vec3(1.), highlight);            // blend in highlight
        
        return col;
    }

    vec4 Mouth(vec2 uv, float smile) {
        uv -= .5;
        vec4 col = vec4(.5, .18, .05, 1.);
        
        uv.y *= 1.5;
        uv.y -= uv.x*uv.x*2.*smile;
        
        uv.x *= mix(2.5, 1., smile);
        
        float d = length(uv);
        col.a = S(.5, .48, d);
        
        vec2 tUv = uv;
        tUv.y += (abs(uv.x)*.5+.1)*(1.-smile);
        float td = length(tUv-vec2(0., .6));
        
        vec3 toothCol = vec3(1.)*S(.6, .35, d);
        col.rgb = mix(col.rgb, toothCol, S(.4, .37, td));
        
        td = length(uv+vec2(0., .5));
        col.rgb = mix(col.rgb, vec3(1., .5, .5), S(.5, .2, td));
        return col;
    }

    vec4 Head(vec2 uv) {
        vec4 col = vec4(.9, .65, .1, 1.);
        
        float d = length(uv);
        
        col.a = S(.5, .49, d);
        
        float edgeShade = remap01(.35, .5, d);
        edgeShade *= edgeShade;
        col.rgb *= 1.-edgeShade*.5;
        
        col.rgb = mix(col.rgb, vec3(.6, .3, .1), S(.47, .48, d));
        
        float highlight = S(.41, .405, d);
        highlight *= remap(.41, -.1, .75, 0., uv.y);
        highlight *= S(.18, .19, length(uv-vec2(.21, .08)));
        col.rgb = mix(col.rgb, vec3(1.), highlight);
        
        d = length(uv-vec2(.25, -.2));
        float cheek = S(.2,.01, d)*.4;
        cheek *= S(.17, .16, d);
        col.rgb = mix(col.rgb, vec3(1., .1, .1), cheek);
        
        return col;
    }

    vec4 Smiley(vec2 uv, vec2 m, float smile) {
        vec4 col = vec4(0.);
        
        if(length(uv)<.5) {    // only bother about pixels that are actually inside the head
            float side = sign(uv.x);
            uv.x = abs(uv.x);
            vec4 head = Head(uv);
            col = mix(col, head, head.a);

            if(length(uv-vec2(.2, .075))<.175) {
                vec4 eye = Eye(within(uv, vec4(.03, -.1, .37, .25)), side, m, smile);
                col = mix(col, eye, eye.a);
            }

            if(length(uv-vec2(.0, -.15))<.3) {
                vec4 mouth = Mouth(within(uv, vec4(-.3, -.43, .3, -.13)), smile);
                col = mix(col, mouth, mouth.a);
            }

            if(length(uv-vec2(.185, .325))<.18) {
                vec4 brow = Brow(within(uv, vec4(.03, .2, .4, .45)), smile);
                col = mix(col, brow, brow.a);
            }
        }
        
        return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        float t = iTime;

        vec2 uv = fragCoord.xy / iResolution.xy;
        uv -= .5;
        uv.x *= iResolution.x/iResolution.y;

        vec2 m = iMouse.xy / iResolution.xy;
        m -= .5;

        if(m.x<-.49 && m.y<-.49) {          // make it that he looks around when the mouse hasn't been used
            float s = sin(t*.5);
            float c = cos(t*.38);

            m = vec2(s, c)*.4;
        }

        if(length(m) > .707) m *= 0.;       // fix bug when coming back from fullscreen

        float d = dot(uv, uv);
        uv -= m*sat(.23-d);

        float smile = sin(t*.5)*.5+.5;
        fragColor = Smiley(uv, m, smile);
    }
    """

    src_km = """
    /////////////////// water highlight
    // Made by k-mouse (2016-11-23)
    // Modified from David Hoskins (2013-07-07) and joltz0r (2013-07-04)

    #define TAU 6.28318530718

    #define TILING_FACTOR 1.0
    #define MAX_ITER 8


    float waterHighlight(vec2 p, float time, float foaminess)
    {
        vec2 i = vec2(p);
        float c = 0.0;
        float foaminess_factor = mix(1.0, 6.0, foaminess);
        float inten = .005 * foaminess_factor;

        for (int n = 0; n < MAX_ITER; n++) 
        {
            float t = time * (1.0 - (3.5 / float(n+1)));
            i = p + vec2(cos(t - i.x) + sin(t + i.y), sin(t - i.y) + cos(t + i.x));
            c += 1.0/length(vec2(p.x / (sin(i.x+t)),p.y / (cos(i.y+t))));
        }
        c = 0.2 + c / (inten * float(MAX_ITER));
        c = 1.17-pow(c, 1.4);
        c = pow(abs(c), 8.0);
        return c / sqrt(foaminess_factor);
    }


    void mainImage( out vec4 fragColor, in vec2 fragCoord ) 
    {
        float time = iTime * 0.1+23.0;
        vec2 uv = fragCoord.xy / iResolution.xy;
        vec2 uv_square = vec2(uv.x * iResolution.x / iResolution.y, uv.y);
        float dist_center = pow(2.0*length(uv - 0.5), 2.0);
        
        float foaminess = smoothstep(0.4, 1.8, dist_center);
        float clearness = 0.1 + 0.9*smoothstep(0.1, 0.5, dist_center);
        
        vec2 p = mod(uv_square*TAU*TILING_FACTOR, TAU)-250.0;
        
        float c = waterHighlight(p, time, foaminess);
        
        vec3 water_color = vec3(0.0, 0.35, 0.5);
        vec3 color = vec3(c);
        color = clamp(color + water_color, 0.0, 1.0);
        
        color = mix(water_color, color, clearness);

        fragColor = vec4(color, 1.0);
    }
    """

    src_tg = """
    ///////////////////Triangle Gradient Background by kbnt
    /* 
       Triangle Gradient Background by kbnt
       License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.

       Inspired by / Remix of "ice and fire" by mattz (https://www.shadertoy.com/view/MdfBzl)
    */

    const float scaleAmnt = 6.2;
    const float motionSpeed = 0.1;
    const float motionSize  = 0.45; // max 0.5
    const float colourSpeed = 0.1;

    /*
    const float s6  = 0.866025388240814208984; // sin(60)
    const float ti6 = 0.577350258827209472656; // cos(60) / sin(60)
    const float si6 = 1.154700517654418945310; // 1 / sin(60)

    const mat2 tri2cart = mat2(s6, -0.5, 0, 1);
    const mat2 cart2tri = mat2(si6, ti6, 0, 1);
    /**/

    /**/
    const float s3 = 1.7320508075688772; // 2 * sin(60)
    const float i3 = 0.5773502691896258; // tan(60)

    const mat2 tri2cart = mat2(1.0, 0.0, -0.5, 0.5*s3);
    const mat2 cart2tri = mat2(1.0, 0.0, i3, 2.0*i3);
    /**/

    /*
    const mat2 tri2cart = mat2(1, 0, 0, 1);
    const mat2 cart2tri = mat2(1, 0, 0, 1);
    /**/

    //////////////////////////////////////////////////////////////////////
    // cosine based palette 
    // adapted from https://www.shadertoy.com/view/ll2GD3

    vec3 pal( in float t, in vec3 a, in vec3 b, in vec3 c, in vec3 d )
    {
        return clamp(a + b*cos( 6.28318*(c*t+d) ), 0.0, 1.0);
    }

    vec3 pala(in float t) {
        return pal( t, vec3(0.5),vec3(0.5),vec3(0.8, 0.8, 0.5),vec3(0, 0.2, 0.5) );
    }

    vec3 colourForPoint(vec2 uv) {
        float t = colourSpeed*iTime;
        
        // pallet sample
        vec3 col00 = pala( t+0.00 );
        vec3 col01 = pala( t+0.25 );
        vec3 col11 = pala( t+0.50 );
        vec3 col10 = pala( t+0.75 );
        
        // mix colours
        vec3 colorA = mix(col00,col10,uv.x);
        vec3 colorB = mix(col01,col11,uv.x);
        return mix(colorA, colorB, uv.y);
    }

    //////////////////////////////////////////////////////////////////////
    // from https://www.shadertoy.com/view/4djSRW

    #define HASHSCALE1 .1031
    #define HASHSCALE3 vec3(443.897, 441.423, 437.195)

    float hash12(vec2 p) {
        vec3 p3  = fract(vec3(p.xyx) * HASHSCALE1);
        p3 += dot(p3, p3.yzx + 19.19);
        return fract((p3.x + p3.y) * p3.z);   
    }

    vec2 hash23(vec3 p3) {
        p3 = fract(p3 * HASHSCALE3);
        p3 += dot(p3, p3.yzx+19.19);
        return fract((p3.xx+p3.yz)*p3.zy);
    }


    //////////////////////////////////////////////////////////////////////
    // generate a random point on a circle from 3 integer coords (x, y, t)

    vec2 randCircle(vec3 p) {
        
        vec2 rt = hash23(p);
        
        float r = sqrt(rt.x);
        float theta = 6.283185307179586 * rt.y;
        
        return r*vec2(cos(theta), sin(theta));
        
    }

    //////////////////////////////////////////////////////////////////////
    // make a time-varying cubic spline at integer coords p that stays
    // inside a unit circle

    vec2 randCircleSpline(vec2 p, float t) {

        // standard catmull-rom spline implementation
        float t1 = floor(t);
        t -= t1;
        
        vec2 pa = randCircle(vec3(p, t1-1.0));
        vec2 p0 = randCircle(vec3(p, t1));
        vec2 p1 = randCircle(vec3(p, t1+1.0));
        vec2 pb = randCircle(vec3(p, t1+2.0));
        
        vec2 m0 = 0.5*(p1 - pa);
        vec2 m1 = 0.5*(pb - p0);
        
        vec2 c3 = 2.0*p0 - 2.0*p1 + m0 + m1;
        vec2 c2 = -3.0*p0 + 3.0*p1 - 2.0*m0 - m1;
        vec2 c1 = m0;
        vec2 c0 = p0;
        
        return (((c3*t + c2)*t + c1)*t + c0) * 0.8;
        
    }

    //////////////////////////////////////////////////////////////////////
    // perturbed point from index

    vec2 triPoint(vec2 p) {
        float t0 = hash12(p);
        return tri2cart*p + motionSize*randCircleSpline(p, motionSpeed*iTime + t0);
    }


    //////////////////////////////////////////////////////////////////////
    // https://stackoverflow.com/questions/2049582/how-to-determine-if-a-point-is-in-a-2d-triangle

    float sgn (vec2 p1, vec2 p2, vec2 p3)
    {
        return (p1.x - p3.x) * (p2.y - p3.y) - (p2.x - p3.x) * (p1.y - p3.y);
    }

    bool PointInTriangle (vec2 pt, vec2 v1, vec2 v2, vec2 v3)
    {
        float d1, d2, d3;
        bool has_neg, has_pos;

        d1 = sgn(pt, v1, v2);
        d2 = sgn(pt, v2, v3);
        d3 = sgn(pt, v3, v1);

        has_neg = (d1 < 0.0) || (d2 < 0.0) || (d3 < 0.0);
        has_pos = (d1 > 0.0) || (d2 > 0.0) || (d3 > 0.0);

        return !(has_neg && has_pos);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {

        // scale from screen space to scene space
        float scl = scaleAmnt / iResolution.y;
       
        // get 2D scene coords
        vec2 p = (fragCoord - 0.5*iResolution.xy) * scl;
        
        // get triangular base coords
        vec2 tfloor = floor(cart2tri * p + 0.5);

        // precompute 9 neighboring points
        vec2 pts[9];

        for (int i=0; i<3; ++i) {
            for (int j=0; j<3; ++j) {
                pts[3*i+j] = triPoint(tfloor + vec2(i-1, j-1));
            }
        }
        
        vec2 center;

        // note: must look at 4 quads cause when the triangle our current  
        //       pixel is in gets randomly nudged in the positive direction,
        //       our pixel may end up in another triangle
        // for each of the 4 quads:
        for (int i=0; i<2; ++i) {
            for (int j=0; j<2; ++j) {

                // look at lower and upper triangle in this quad
                vec2 t00 = pts[3*i+j  ];
                vec2 t10 = pts[3*i+j+3];
                vec2 t01 = pts[3*i+j+1];
                vec2 t11 = pts[3*i+j+4];

                // lower
                if (PointInTriangle(p, t00, t10, t11)) 
                    center = (t00 + t10 + t11) / 3.0; // get centeroid of triangle

                // upper
                if (PointInTriangle(p, t00, t11, t01))
                    center = (t00 + t11 + t01) / 3.0;
            }
        }

        // convert from scene space to uv to sample colour 
        center = center / scl;
        center += 0.5*iResolution.xy;
        center += 0.5;
        center = center / iResolution.xy;

        vec4 col = vec4(colourForPoint(center), 1.0);

        // final pixel color
        fragColor = col;
    }
    """

    src_sd = """
    //////////////////////// shadow dance
    #define SPEED 0.2
    #define PI 3.14159265359

    // alternate the direction of rotation along a checker pattern
    #define CHECKERED


    mat2 rot(float angle) {
        return mat2(cos(angle), -sin(angle),
                    sin(angle), cos(angle));
    }

    float checkersign(vec2 uv) {
    #ifdef CHECKERED
        uv = floor(uv);
        return sign(mod(uv.x + uv.y, 2.) - .5);
    #else
        return 1.;
    #endif
    }

    vec3 mod289(vec3 x) {
      return x - floor(x * (1.0 / 289.0)) * 289.0;
    }

    vec4 mod289(vec4 x) {
      return x - floor(x * (1.0 / 289.0)) * 289.0;
    }

    vec4 permute(vec4 x) {
         return mod289(((x*34.0)+1.0)*x);
    }

    vec4 taylorInvSqrt(vec4 r)
    {
      return 1.79284291400159 - 0.85373472095314 * r;
    }

    // https://github.com/ashima/webgl-noise/blob/master/src/noise3Dgrad.glsl
    // modified to allow for rotation 
    float snoise(vec3 v, out vec3 gradient, float time)
    {
      const vec2  C = vec2(1.0/6.0, 1.0/3.0) ;
      const vec4  D = vec4(0.0, 0.5, 1.0, 2.0);

    // First corner
      vec3 i  = floor(v + dot(v, C.yyy) );
      vec3 x0 =   v - i + dot(i, C.xxx) ;

    // Other corners
      vec3 g = step(x0.yzx, x0.xyz);
      vec3 l = 1.0 - g;
      vec3 i1 = min( g.xyz, l.zxy );
      vec3 i2 = max( g.xyz, l.zxy );

      //   x0 = x0 - 0.0 + 0.0 * C.xxx;
      //   x1 = x0 - i1  + 1.0 * C.xxx;
      //   x2 = x0 - i2  + 2.0 * C.xxx;
      //   x3 = x0 - 1.0 + 3.0 * C.xxx;
      vec3 x1 = x0 - i1 + C.xxx;
      vec3 x2 = x0 - i2 + C.yyy; // 2.0*C.x = 1/3 = C.y
      vec3 x3 = x0 - D.yyy;      // -1.0+3.0*C.x = -0.5 = -D.y

    // Permutations
      i = mod289(i); 
      vec4 p = permute( permute( permute( 
                 i.z + vec4(0.0, i1.z, i2.z, 1.0 ))
               + i.y + vec4(0.0, i1.y, i2.y, 1.0 )) 
               + i.x + vec4(0.0, i1.x, i2.x, 1.0 ));
        
    // Gradients: 7x7 points over a square, mapped onto an octahedron.
    // The ring size 17*17 = 289 is close to a multiple of 49 (49*6 = 294)
      float n_ = 0.142857142857; // 1.0/7.0
      vec3  ns = n_ * D.wyz - D.xzx;
        
      vec4 j = p - 49.0 * floor(p * ns.z * ns.z);  //  mod(p,7*7)

      vec4 x_ = floor(j * ns.z);
      vec4 y_ = floor(j - 7.0 * x_ );    // mod(j,N)

      vec4 x = x_ *ns.x + ns.yyyy;
      vec4 y = y_ *ns.x + ns.yyyy;
      vec4 h = 1.0 - abs(x) - abs(y);

      vec4 b0 = vec4( x.xy, y.xy );
      vec4 b1 = vec4( x.zw, y.zw );

      //vec4 s0 = vec4(lessThan(b0,0.0))*2.0 - 1.0;
      //vec4 s1 = vec4(lessThan(b1,0.0))*2.0 - 1.0;
      vec4 s0 = floor(b0)*2.0 + 1.0;
      vec4 s1 = floor(b1)*2.0 + 1.0;
      vec4 sh = -step(h, vec4(0.0));

      vec4 a0 = b0.xzyw + s0.xzyw*sh.xxyy ;
      vec4 a1 = b1.xzyw + s1.xzyw*sh.zzww ;

      vec3 p0 = vec3(a0.xy,h.x);
      vec3 p1 = vec3(a0.zw,h.y);
      vec3 p2 = vec3(a1.xy,h.z);
      vec3 p3 = vec3(a1.zw,h.w);

    //Normalise gradients
      vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2, p2), dot(p3,p3)));
      p0 *= norm.x;
      p1 *= norm.y;
      p2 *= norm.z;
      p3 *= norm.w;

    // add rotation
      x0.xy *= rot(time*checkersign(a0.xy));
      x1.xy *= rot(time*checkersign(a0.zw));
      x2.xy *= rot(time*checkersign(a1.xy));
      x3.xy *= rot(time*checkersign(a1.zw));
        
    // Mix final noise value
      vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
      vec4 m2 = m * m;
      vec4 m4 = m2 * m2;
      vec4 pdotx = vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3));

    // Determine noise gradient
      vec4 temp = m2 * m * pdotx;
      gradient = -8.0 * (temp.x * x0 + temp.y * x1 + temp.z * x2 + temp.w * x3);
      gradient += m4.x * p0 + m4.y * p1 + m4.z * p2 + m4.w * p3;
      gradient *= 42.0;

      return 420.0 * dot(m4, pdotx);//origin 42->420 Kiri
    }

    float get_mask(vec2 uv) {
        uv.y *= 4.;
        uv.y -= 1.;
        uv.x *= .6;
        uv.x *= pow(uv.y, .15);
        uv.x = abs(uv.x);
        return (smoothstep(0.65, 1., uv.x) * step(0., uv.y));
    }

    float fbm(vec3 p, inout vec3 gradient) {
        // Initial values
        float value = 0.;
        float amplitude = .3;
        float frequency = 1.;
        float rotation = 1.5;
        vec3 grad;
        // Loop of octaves
        for (int i = 0; i < 4; i++) {
            value += amplitude * snoise(frequency*p - gradient, grad, iTime*rotation);
            grad.z = 0.;
            gradient += amplitude*grad*.3;
            frequency *= 2.;
            amplitude *= .5;
            rotation *= 2.;
        }
        return value;
    }
    int HASH[256] = int[256](
        208, 34,  231, 213, 32,  248, 233, 56,  161, 78,  24,  140, 71,  48,  140,
        254, 245, 255, 247, 247, 40,  185, 248, 251, 245, 28,  124, 204, 204, 76,
        36,  1,   107, 28,  234, 163, 202, 224, 245, 128, 167, 204, 9,   92,  217,
        54,  239, 174, 173, 102, 193, 189, 190, 121, 100, 108, 167, 44,  43,  77,
        180, 204, 8,   81,  70,  223, 11,  38,  24,  254, 210, 210, 177, 32,  81,
        195, 243, 125, 8,   169, 112, 32,  97,  53,  195, 13,  203, 9,   47,  104,
        125, 117, 114, 124, 165, 203, 181, 235, 193, 206, 70,  180, 174, 0,   167,
        181, 41,  164, 30,  116, 127, 198, 245, 146, 87,  224, 149, 206, 57,  4,
        192, 210, 65,  210, 129, 240, 178, 105, 228, 108, 245, 148, 140, 40,  35,
        195, 38,  58,  65,  207, 215, 253, 65,  85,  208, 76,  62,  3,   237, 55,
        89,  232, 50,  217, 64,  244, 157, 199, 121, 252, 90,  17,  212, 203, 149,
        152, 140, 187, 234, 177, 73,  174, 193, 100, 192, 143, 97,  53,  145, 135,
        19,  103, 13,  90,  135, 151, 199, 91,  239, 247, 33,  39,  145, 101, 120,
        99,  3,   186, 86,  99,  41,  237, 203, 111, 79,  220, 135, 158, 42,  30,
        154, 120, 67,  87,  167, 135, 176, 183, 191, 253, 115, 184, 21,  233, 58,
        129, 233, 142, 39,  128, 211, 118, 137, 139, 255, 114, 20,  218, 113, 154,
        27,  127, 246, 250, 1,   8,   198, 250, 209, 92,  222, 173, 21,  88,  102,
        219);

    int noise2(int x, int y, int seed) {
      int yindex = (y + seed) % 256;
      if (yindex < 0) yindex += 256;
      int xindex = (HASH[yindex] + x) % 256;
      if (xindex < 0) xindex += 256;
      return HASH[xindex];
    }

    float lin_inter(float x, float y, float s) {
      return x + s * (y - x);
    }

    float smooth_inter(float x, float y, float s) {
      return lin_inter(x, y, s * s * (3. - 2. * s));
    }

    float noise2d(float x, float y, int seed) {
      int x_int = int(floor(x));
      int y_int = int(floor(y));
      float x_frac = float(x - float(x_int));
      float y_frac = y - float(y_int);
      int s = noise2(x_int, y_int, seed);
      int t = noise2(x_int + 1, y_int, seed);
      int u = noise2(x_int, y_int + 1, seed);
      int v = noise2(x_int + 1, y_int + 1, seed);
      float low = smooth_inter(float(s), float(t), float(x_frac));
      float high = smooth_inter(float(u), float(v), float(x_frac));
      return smooth_inter(float(low), float(high), float(y_frac));
    }

    float perlin_get2d(vec2 p, float freq, int depth, int seed) {
      depth = min(depth, 8); // too slow otherwise
      float xa = p.x * freq;
      float ya = p.y * freq;
      float amp = 1.0;
      float fin = 0.;
      float div = 0.0;
      for (int i = 0; i < depth; i++) {
        div += 256. * amp;
        fin += noise2d(xa, ya, seed) * amp;
        amp /= 2.;
        xa *= 2.;
        ya *= 2.;
      }
      return clamp(fin / div, -1.0, 1.0);
    }

    float perlin_get2d(vec2 p, float freq, float depth, float seed) {
      return perlin_get2d(p, freq, int(depth), int(seed));
    }

    vec3 perlin_vec3(vec2 p, float freq, int depth, int seed) {
      float x = perlin_get2d(p, freq, depth, seed);
      float y = perlin_get2d(p, freq, depth, int(seed+int(freq)));
      float z = perlin_get2d(p, freq, depth, int(seed+int(ceil(freq))+int(ceil(freq))));
      
      return vec3(x, y, z);
    }
    vec3 smoke(vec2 uv, vec2 px, vec2 res) {
      float T = iTime*SPEED;
      uv = (0.5+uv);
      uv *= 0.25;
      const float freq = 6.6;

      float n0 = perlin_get2d(uv+vec2(cos(T*0.1)*0.5, -T*0.33), freq*2.0, 4, 96739);

      float radius = res.x*(0.25*(0.25+n0));
      float feather = radius;

      vec2 center = res * 0.5;
      center.y += res.y*0.25;
      float distCenter = length(center - px);
      float magCenter = 1.0-smoothstep(radius-feather, radius+feather, distCenter);

      vec2 move = vec2(0, -(1.0+(T*0.9)));
      vec3 p3_1 = perlin_vec3(uv+(move*0.1), freq, 4, 8371);
      move += vec2(0.05, 0.1)*vec2(cos(p3_1.x+T+(uv.y/1.6)), sin((uv.x/1.6)+p3_1.y+T));

      float n1 = perlin_get2d(uv+move, freq*2.0, 4, 26122);

      float f = magCenter;
      float n = (n0+n1)/2.0;

      return vec3(n) * f * 1.6;
    }

    #define FIRE_COLOR_0 (vec3(213.0, 77., 0.0) / 255.0)
    #define FIRE_COLOR_1 (vec3(253.0, 253.0, 46.0) / 255.0)
    #define FIRE_COLOR_2 (vec3(1.0))
    #define FIRE_COLOR_3 (vec3(1.0, 0.001, 0.002))

    vec3 fire(vec2 uv, vec2 px, vec2 res, vec3 sm) {
      sm *= 0.45;
      float T = iTime*SPEED;
      uv = (0.5+uv);
      uv *= 0.25;
      const float freq = 6.6;
      float n0 = perlin_get2d(uv+vec2(cos(T*0.1+sm.x)*0.5, -T*0.33+sm.y), freq*2.0, 4, 17397);
      float n1 = perlin_get2d(uv*n0, freq, 4, 9384);
      float n2 = perlin_get2d(vec2(n0+sm.y, n1+sm.x), freq, 4, 2525);
      float n3 = perlin_get2d(uv*vec2(n1, n2)*3.3, freq*1.6, 3, 9285);

      float radius = res.x*(0.25*(0.25+n0));
      float feather = radius*0.6;

      vec2 center = res * 0.5;
      center.y += radius*0.05;
      center.y -= res.y * 0.21;
      float distCenter = length(center - px);
      float magCenter = 1.0-smoothstep(radius-feather, radius+feather, distCenter)*0.;

      vec3 color = mix(FIRE_COLOR_0, FIRE_COLOR_1, n2);
      color = mix(color, FIRE_COLOR_2, pow((magCenter*0.5)+((n0+n1)*0.33), 3.6));
      color = mix(color, FIRE_COLOR_3, pow(n3, 2.2));

      float f = pow(magCenter, 2.5);

      f = clamp(f, 0.0, 1.0);

      return color * f;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord/iResolution.xy;

        vec3 col = vec3(0.0);
        vec3 sm = smoke(uv, fragCoord.xy, iResolution.xy);
        vec3 fir = fire(uv, fragCoord.xy, iResolution.xy, sm);

        col += sm + fir;

        uv.x = uv.x*2.-1.;
        uv.x *= iResolution.x / iResolution.y; 

        float mask = get_mask(uv);

        vec3 background = vec3(0.,0.,0.);//texture(iChannel0, uv).rgb;
        
        vec3 p = vec3(uv, 0.);
        p.x *= pow(p.y, .3);
        p.y = pow(p.y, .5);

        vec3 gradient = vec3(0.);
        float noise = fbm(p + vec3(0., iTime*.06, 0.), gradient);
        noise = noise*.5+.5;

        col *= mix(vec3(noise)*vec3(0.6, .6, .9)*2.,vec3(0.), mask);

        fragColor = vec4(col.r*.7,col.g*.5,col.b*.3,1.0);
    }
    """

    src_ns = """
    ///////////////////Neon Sunset
    // License CC0: Neon Sunset
    //  Code is hackish but I thought it looked good enough to share
    //  The music from GTA III - RISE FM, the best radio channel in GTA III IMHO
    #define LAYERS            5.0
    #define PI                3.141592654
    #define TAU               (2.0*PI)
    #define TIME              iTime
    #define TTIME             (TAU*TIME)
    #define RESOLUTION        iResolution
    #define ROT(a)            mat2(cos(a), sin(a), -sin(a), cos(a))

    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    float sRGB(float t) { return mix(1.055*pow(t, 1./2.4) - 0.055, 12.92*t, step(t, 0.0031308)); }
    // License: Unknown, author: nmz (twitter: @stormoid), found: https://www.shadertoy.com/view/NdfyRM
    vec3 sRGB(in vec3 c) { return vec3 (sRGB(c.x), sRGB(c.y), sRGB(c.z)); }

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6f;
      float a = 2.51f;
      float b = 0.03f;
      float c = 2.43f;
      float d = 0.59f;
      float e = 0.14f;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0f, 1.0f);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float hash(float co) {
      return fract(sin(co*12.9898) * 13758.5453);
    }

    // License: Unknown, author: Unknown, found: don't remember
    vec2 hash2(vec2 p) {
      p = vec2(dot (p, vec2 (127.1, 311.7)), dot (p, vec2 (269.5, 183.3)));
      return fract(sin(p)*43758.5453123);
    }

    // License: CC BY-NC-SA 3.0, author: Stephane Cuillerdier - Aiekick/2015 (twitter:@aiekick), found: https://www.shadertoy.com/view/Mt3GW2
    vec3 blackbody(float Temp) {
      vec3 col = vec3(255.);
      col.x = 56100000. * pow(Temp,(-3. / 2.)) + 148.;
      col.y = 100.04 * log(Temp) - 623.6;
      if (Temp > 6500.) col.y = 35200000. * pow(Temp,(-3. / 2.)) + 184.;
      col.z = 194.18 * log(Temp) - 1448.6;
      col = clamp(col, 0., 255.)/255.;
      if (Temp < 1000.) col *= Temp/1000.;
      return col;
    }

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    // License: Unknown, author: Unknown, found: don't remember
    float tanh_approx(float x) {
    //  return tanh(x);
      float x2 = x*x;
      return clamp(x*(27.0 + x2)/(27.0+9.0*x2), -1.0, 1.0);
    }

    float circle(vec2 p, float r) {
      return length(p) - r;
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/articles/smin
    float pmin(float a, float b, float k) {
        float h = clamp( 0.5+0.5*(b-a)/k, 0.0, 1.0 );
        return mix( b, a, h ) - k*h*(1.0-h);
    }

    // License: MIT OR CC-BY-NC-4.0, author: mercury, found: https://mercury.sexy/hg_sdf/
    float mod1(inout float p, float size) {
      float halfsize = size*0.5;
      float c = floor((p + halfsize)/size);
      p = mod(p + halfsize, size) - halfsize;
      return c;
    }

    // License: MIT OR CC-BY-NC-4.0, author: mercury, found: https://mercury.sexy/hg_sdf/
    vec2 mod2(inout vec2 p, vec2 size) {
      vec2 c = floor((p + size*0.5)/size);
      p = mod(p + size*0.5,size) - size*0.5;
      return c;
    }

    // License: MIT, author: Inigo Quilez, found: https://iquilezles.org/articles/intersectors
    float rayPlane(vec3 ro, vec3 rd, vec4 p) {
      return -(dot(ro,p.xyz)+p.w)/dot(rd,p.xyz);
    }

    vec3 toSpherical(vec3 p) {
      float r   = length(p);
      float t   = acos(p.z/r);
      float ph  = atan(p.y, p.x);
      return vec3(r, t, ph);
    }

    float sun(vec2 p) {
      const float ch = 0.0125;
      vec2 sp = p;
      float d0 = circle(sp, 0.5);
      float d = d0;
      return d;
    }

    float segmentx(vec2 p) {
      float d0 = abs(p.y);
      float d1 = length(p);
      return p.x > 0.0 ? d0 : d1;
    }

    float segmentx(vec2 p, float l) {
      float hl = 0.5*l;
      p.x = abs(p.x);
      float d0 = abs(p.y);
      float d1 = length(p-vec2(hl, 0.0));
      return p.x > hl ? d1 : d0;
    }

    float synth(vec2 p, float aa, out float h, out float db) {
      const float z = 75.0;
      p.y -= -70.0;
      const float st = 0.04;
      p.x = abs(p.x);
      p.x -= 20.0-3.5;
      p.x += st*20.0;
      p /= z;
      float n = mod1(p.x, st);
      float dib = 1E6;
      const int around = 0;
      for (int i = -around; i <=around ;++i) {
        float fft = texture(iChannel0, vec2((n+float(i))*st, 0.25)).x; 
        fft *= fft;
        if (i == 0) h = fft;
        float dibb = segmentx((p-vec2(st*float(i), 0.0)).yx, fft+0.05)-st*0.4;
        dib = min(dib, dibb);
      }
      
      float d = dib;
      db = abs(p.y)*z;
      return smoothstep(aa, -aa, d*z);
    }

    vec3 road(vec3 ro, vec3 rd, vec3 nrd, float glare, vec4 pl, out float pt) {
      const float szoom   = 0.5;
      const float bsz     = 25.0;
      const float sm      = 1.0;
      float off = abs(pl.w);
      float t = rayPlane(ro, rd, pl);
      pt = t;

      vec3 p  = ro+rd*t;
      vec3 np = ro+nrd*t;

      vec2 pp   = p.xz;
      vec2 npp  = np.xz;
      vec2 opp  = pp;

      float aa  = length(npp-pp)*sqrt(0.5);
      pp.y += -60.0*TIME;

      vec3 gcol = vec3(0.0);

      float dr = abs(pp.x)-off;
      vec2 cp = pp;
      mod1(cp.y, 6.0*off);
      vec2 sp = pp;
      sp.x = abs(sp.x);
      mod1(sp.y, off);
      float dcl = segmentx(cp.yx, 1.5*off);
      float dsl = segmentx((sp-vec2(0.95*off, 0.0)).yx, off*0.5);

      vec2 mp = pp;
      mod2(mp, vec2(off*0.5));
        
      vec2 dp = abs(mp);
      float d = dp.x;
      d = pmin(d, dp.y, sm);
      d = max(d, -dr);
      d = min(d, dcl); 
      d = min(d, dsl); 
      vec2 s2 = sin(TIME+2.0*p.xz/off);
      float m = mix(0.75, 0.9, tanh_approx(s2.x+s2.y));
      m *= m;
      m *= m;
      m *= m;
      vec3 hsv = vec3(0.4+mix(0.5, 0.0, m), tanh_approx(0.15*mix(30.0, 10.0, m)*d), 1.0);
      float fo = exp(-0.04*max(abs(t)-off*2., 0.0));
      vec3 bcol = hsv2rgb(hsv);
      gcol += 2.0*bcol*exp(-0.1*mix(30.0, 10.0, m)*d)*fo;

      float sh;
      float sdb;
      float sd =synth(opp, aa,sh, sdb)*smoothstep(aa, -aa, -dr);
      sh = tanh_approx(sh);
      sdb *= 0.075;
      sdb *= sdb;
      sdb += 0.05;
      vec3 scol = sd*(sdb)*pow(tanh(vec3(0.1)+bcol), mix(vec3(1.0), vec3(1.5, 0.5, 0.5), smoothstep(0.4, 0.5, sh)));
      gcol += scol;


      gcol = t > 0.0 ? gcol : vec3(0.0);
      return gcol+scol;
    }

    vec3 stars(vec2 sp, float hh) {
      vec3 col = vec3(0.0);
      
      const float m = LAYERS;
      hh = tanh_approx(20.0*hh);

      for (float i = 0.0; i < m; ++i) {
        vec2 pp = sp+0.5*i;
        float s = i/(m-1.0);
        vec2 dim  = vec2(mix(0.05, 0.003, s)*PI);
        vec2 np = mod2(pp, dim);
        vec2 h = hash2(np+127.0+i);
        vec2 o = -1.0+2.0*h;
        float y = sin(sp.x);
        pp += o*dim*0.5;
        pp.y *= y;
        float l = length(pp);
      
        float h1 = fract(h.x*1667.0);
        float h2 = fract(h.x*1887.0);
        float h3 = fract(h.x*2997.0);

        vec3 scol = mix(8.0*h2, 0.25*h2*h2, s)*blackbody(mix(3000.0, 22000.0, h1*h1));

        vec3 ccol = col + exp(-(mix(6000.0, 2000.0, hh)/mix(2.0, 0.25, s))*max(l-0.001, 0.0))*scol;
        ccol *= mix(0.125, 1.0, smoothstep(1.0, 0.99, sin(0.25*TIME+TAU*h.y)));
        col = h3 < y ? ccol : col;
      }
      
      return col;
    }

    vec3 meteorite(vec2 sp) {
      const float period = 3.0;
      float mtime = mod(TIME, period);
      float ntime = floor(TIME/period);
      float h0 = hash(ntime+123.4);
      float h1 = fract(1667.0*h0);
      float h2 = fract(9967.0*h0);
      vec2 mp = sp;
      mp.x += -1.0;
      mp.y += -0.5*h1;
      mp.y += PI*0.5;
      mp *= ROT(PI+mix(-PI/4.0, PI/4.0, h0));
      float m = mtime/period;
      mp.x += mix(-1.0, 2.0, m);
      
      float d0 = length(mp);
      float d1 = segmentx(mp);
      
      vec3 col = vec3(0.0);
      
      col += 0.5*exp(-4.0*max(d0, 0.0))*exp(-1000.0*max(d1, 0.0));
      col *= 2.0*HSV2RGB(vec3(0.8, 0.5, 1.0));
      float fl = smoothstep(-0.5, 0.5, sin(12.0*TTIME));
      col += mix(1.0, 0.5, fl)*exp(-mix(100.0, 150.0, fl)*max(d0, 0.0));
      
      col = h2 > 0.8 ? col: vec3(0.0);
      return col;
    }

    vec3 skyGrid(vec2 sp) {
      const float m = 1.0;

      const vec2 dim = vec2(1.0/12.0*PI);
      float y = sin(sp.x);
      vec2 pp = sp;
      vec2 np = mod2(pp, dim*vec2(1.0/floor(1.0/y), 1.0));

      vec3 col = vec3(0.0);

      float d = min(abs(pp.x), abs(pp.y*y));
      
      float aa = 2.0/RESOLUTION.y;
      
      col += 0.25*vec3(0.5, 0.5, 1.0)*exp(-2000.0*max(d-0.00025, 0.0));
      
      return col;
    }

    vec3 sunset(vec2 sp, vec2 nsp) {
      const float szoom   = 0.5;
      float aa = length(nsp-sp)*sqrt(0.5);
      sp -= vec2(vec2(0.5, -0.5)*PI);
      sp /= szoom;
      sp = sp.yx;
      sp.y += 0.22;
      sp.y = -sp.y;
      float ds = sun(sp)*szoom;
      
      vec3 bscol = hsv2rgb(vec3(fract(0.7-0.25*(sp.y)), 1.0, 1.0));
      vec3 gscol = 0.75*sqrt(bscol)*exp(-50.0*max(ds, 0.0));
      vec3 scol = mix(gscol, bscol, smoothstep(aa, -aa, ds));
      return scol;
    }

    vec3 glow(vec3 ro, vec3 rd, vec2 sp, vec3 lp) {
      float ld = max(dot(normalize(lp-ro), rd),0.0);
      float y = -0.5+sp.x/PI;
      y = max(abs(y)-0.02, 0.0)+0.1*smoothstep(0.5, PI, abs(sp.y));
      float ci = pow(ld, 10.0)*2.0*exp(-25.0*y);
      float h = 0.65;
      vec3 col = hsv2rgb(vec3(h, 0.75, 0.35*exp(-15.0*y)))+HSV2RGB(vec3(0.8, 0.75, 0.5))*ci;
      return col;
    }

    vec3 neonSky(vec3 ro, vec3 rd, vec3 nrd, out float gl) {
      const vec3 lp       = 500.0*vec3(0.0, 0.25, -1.0);
      const vec3 skyCol   = HSV2RGB(vec3(0.8, 0.75, 0.05));

      float glare = pow(abs(dot(rd, normalize(lp))), 20.0);
      
      vec2 sp   = toSpherical(rd.xzy).yz;
      vec2 nsp  = toSpherical(nrd.xzy).yz;
      vec3 grd  = rd;
      grd.xy *= ROT(0.025*TIME);
      vec2 spp = toSpherical(grd).yz;

      float gm = 1.0/abs(rd.y)*mix(0.005, 2.0, glare);
      vec3 col = skyCol*gm;
      float ig = 1.0-glare;
      col += glow(ro, rd, sp, lp);
      if (rd.y > 0.0) {
        col += sunset(sp, nsp);
        col += stars(sp, 0.0)*ig;
        col += skyGrid(spp)*ig;
        col += meteorite(sp)*ig;
      }
      gl = glare;
      return col;
    }

    vec3 color(vec3 ro, vec3 rd, vec3 nrd) {
      const float off1  = -20.0;
      const vec4 pl1    = vec4(normalize(vec3(0.0, 1.0, 0.15)), -off1);
      float glare;
      vec3 col = neonSky(ro, rd, nrd, glare);
      if (rd.y < 0.0) {
        float t;
        col += road(ro, rd, nrd, glare, pl1, t);
      }
      return col;
    }

    void mainImage(out vec4 fragColor, in vec2 fragCoord) {
      vec2 q = fragCoord/RESOLUTION.xy; 
      vec2 p = -1.0 + 2.0*q;
      p.x *= RESOLUTION.x/RESOLUTION.y;
      float aa = 2.0/RESOLUTION.y;
      vec3 ro = vec3(0.0, 0.0, 10.0);
      vec3 la = vec3(0.0, 2.0, 0.0);
      vec3 up = vec3(0.0, 1.0, 0.0);

      vec3 ww = normalize(la - ro);
      vec3 uu = normalize(cross(up, ww ));
      vec3 vv = normalize(cross(ww,uu));
      const float fov = tan(TAU/6.0);
      vec2 np = p + vec2(aa); 
      vec3 rd = normalize(-p.x*uu + p.y*vv + fov*ww);
      vec3 nrd = normalize(-np.x*uu + np.y*vv + fov*ww);

      vec3 col = vec3(0.1);
      col = color(ro, rd, nrd);
    //  col += synth(p, np);
      col *= smoothstep(0.0, 4.0, TIME);
      col = aces_approx(col);
      col = sRGB(col); 

      fragColor = vec4(col, 1.0);
    }
    """

    src_ssl = """
    ///////////////////Synthwave sunset logo

    #define AA 2
    #define NH 4
    #define NV 12
    #define PI 3.14159265

    float prm(float a, float b, float x) {
        return clamp((x - a) / (b - a) , 0.0, 1.0);
    }

    float par(float x) {
        return 1.0 - pow(2.0 * x - 1.0, 2.0);
    }

    float length_sq(vec2 x) {
        return dot(x, x);
    }

    float segment_df(vec2 uv, vec2 p0, vec2 p1) {
      float l2 = length_sq(p1 - p0);
      float t = clamp(dot(uv - p0, p1 - p0) / l2, 0.0, 1.0);
      vec2 projection = p0 + t * (p1 - p0);
      return distance(uv, projection);
    }

    // https://stackoverflow.com/a/2049593/8259873
    float segment_side(vec2 p0, vec2 p1, vec2 p2)
    {
        return (p0.x - p2.x) * (p1.y - p2.y) - (p1.x - p2.x) * (p0.y - p2.y);
    }

    bool triangle_in(vec2 uv, vec2 p0, vec2 p1, vec2 p2)
    {
        float d0 = segment_side(uv, p0, p1);
        float d1 = segment_side(uv, p1, p2);
        float d2 = segment_side(uv, p2, p0);

        bool has_neg = (d0 < 0.0) || (d1 < 0.0) || (d2 < 0.0);
        bool has_pos = (d0 > 0.0) || (d1 > 0.0) || (d2 > 0.0);

        return !(has_neg && has_pos);
    }

    float triangle_sdf(vec2 uv, vec2 p0, vec2 p1, vec2 p2) {
        float p0p1 = segment_df(uv, p0, p1);
        float p1p2 = segment_df(uv, p1, p2);
        float p2p0 = segment_df(uv, p2, p0);
        float abs_diff = min(p0p1, min(p1p2, p2p0));
        return triangle_in(uv, p0, p1, p2) ? -abs_diff : abs_diff;
    }

    float sun_sdf(vec2 uv) {
        bool is_in = true;
        float t = mod(iTime, 4.0) / 4.0;
        float lo[7] = float[7](0.2, 0.03, -0.14, -0.31, -0.48, -0.65, -0.8);
        float hi[7] = float[7](0.2, 0.05, -0.1, -0.25, -0.4, -0.55, -0.7);
        float bands_sdf = 10.0;
        for(int i = 0; i < 6; i++) {
            float low = mix(lo[i+1], lo[i], t);
            float high = mix(hi[i+1], hi[i], t);
            float band_sdf = max(uv.y-high, low-uv.y);
            bands_sdf = min(bands_sdf, band_sdf);
        }
        float circle_sdf = length(uv) - 0.7;
        return max(circle_sdf, -bands_sdf);
    }

    float sq(float x) {
        return x * x;
    }

    bool palm_in(vec2 uv) {
        const float ah[NH] = float[NH](0.1, 0.25, 1.5, 2.5);
        const float bh[NH] = float[NH](0.2, 0.75, -0.37, -0.17);
        const float ch[NH] = float[NH](-0.17, 0.07, -0.147, 0.255);
        const float dh[NH] = float[NH](-0.8, -0.8, 0.3, 0.1);
        const float eh[NH] = float[NH](0.3, 0.1, 0.57, 0.37);
        const float fh[NH] = float[NH](-1.7, -1.7, 0.3, 0.1);
        const float gh[NH] = float[NH](0.3, 0.1, 0.57, 0.37);
        const float th0[NH] = float[NH](0.01, 0.01, 0.005, 0.005);
        const float th1[NH] = float[NH](0.03, 0.03, 0.03, 0.03);

        bool h_in = false;
        for(int i = 0; i < NH; i++) {
            float h_dist = abs(uv.x - (ah[i] * sq(uv.y + bh[i]) + ch[i]));
            h_in = h_in || h_dist < mix(th0[i], th1[i], par(prm(fh[i], gh[i], uv.y)))
                && uv.y > dh[i] && uv.y < eh[i];
        }
        
        const float av[NV] = float[NV](-2.7, -1.6, -3.5, -3.5, -2.0, -2.5,
                                       -2.0, -1.6, -3.0, -3.5, -2.5, -3.0);
        const float bv[NV] = float[NV](0.17, 0.3, 0.35, -0.095, -0.02, 0.2,
                                       -0.225, -0.095, -0.045, -0.495, -0.4, -0.248);
        const float cv[NV] = float[NV](0.3, 0.35, 0.46, 0.5, 0.35, 0.31,
                                       0.1, 0.15, 0.25, 0.3, 0.15, 0.1);
        const float dv[NV] = float[NV](-0.5, -0.65, -0.5, -0.15, -0.15, -0.15,
                                       -0.155, -0.255, -0.1, 0.26, 0.26, 0.25);
        const float ev[NV] = float[NV](-0.14, -0.14, -0.14, 0.15, 0.25, 0.15,
                                       0.255, 0.255, 0.255, 0.57, 0.645, 0.545);

        bool v_in = false;
        for(int i = 0; i < NV; i++) {
            float v_dist = abs(uv.y - (av[i] * sq(uv.x + bv[i]) + cv[i]));
            v_in = v_in || v_dist < mix(0.005, 0.04, par(prm(dv[i], ev[i], uv.x)))
                && uv.x > dv[i] && uv.x < ev[i];
        }

        return h_in || v_in;
    }

    mat2 rotation_mat(float alpha) {
        float c = cos(alpha);
        float s = sin(alpha);
        return mat2(c, s, -s, c);
    }

    vec4 sampleColor(in vec2 sampleCoord)
    {
        // uv is centered and such that the vertical values are between -1
        // and 1 while preserving the aspect ratio.
        vec2 uv = 2.0* (sampleCoord - iResolution.xy / 2.0) / iResolution.y;

        const vec3 BG = vec3(0.1, 0.1, 0.2);
        vec3 cyan = vec3(0.3, 0.85, 1);
        vec3 magenta = vec3(1, 0.1, 1);
        float t = sin(0.3 * cos(0.2 * iTime) * uv.x + uv.y + 1.0 + 0.15 * cos(0.3 * iTime));
        vec3 cm = mix(cyan, magenta, t*t);
        vec3 mc = mix(magenta, cyan, t*t);
        
        vec2 a = vec2(0, -0.9);
        vec2 b = vec2(-1.0, 0.4);
        vec2 c = vec2(1.1, 0.6);
        
        float alpha = 0.25 * cos(0.5 * iTime);
        float gamma = -0.1 + 0.2 * cos(PI + 0.5 * iTime);
        float beta = (alpha + gamma) / 2.0;
        mat2 alpha_mat = rotation_mat(alpha);
        mat2 beta_mat = rotation_mat(beta);
        mat2 gamma_mat = rotation_mat(gamma);

        vec2 t0a = alpha_mat * a;
        vec2 t0b = alpha_mat * b;
        vec2 t0c = alpha_mat * c;
        vec2 t1b = mix(t0a, t0b, 3.0);
        vec2 t1c = mix(t0a, t0c, 3.0);
        vec2 t2a = beta_mat * a;
        vec2 t2b = beta_mat * b;
        vec2 t2c = beta_mat * c;
        vec2 t3a = gamma_mat * a;
        vec2 t3b = gamma_mat * b;
        vec2 t3c = gamma_mat * c;
        
        float sun = sun_sdf(uv);
        bool palm = palm_in(uv);
        float tri0_sdf = triangle_sdf(uv, t0a, t0b, t0c);
        float tri1_sdf = triangle_sdf(uv, t0a, t1b, t1c);
        float tri2_sdf = triangle_sdf(uv, t2a, t2b, t2c);
        float tri3_sdf = triangle_sdf(uv, t3a, t3b, t3c);
        
        vec3 col = BG;
        
        if(tri3_sdf < 0.0) col = vec3(0);
        else if(tri3_sdf < 0.01) col = mc;
        if(tri2_sdf < 0.0) col = mc;
        if(tri0_sdf < 0.0) col = vec3(0);
        else if(tri0_sdf < 0.01) col = mc;
        if(tri1_sdf < 0.0) col = mix(cm, col, smoothstep(0.0, 0.01, sun));
        if(tri1_sdf < 0.0 && palm) col = vec3(0);

        return vec4(col, 1.0);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
        vec4 colSum = vec4(0);
        for(int i = 0; i < AA; i++) {
            for(int j = 0; j < AA; j++) {
                colSum += sampleColor(fragCoord + vec2(float(i) / float(AA), float(j) / float(AA)));
            }
        }
        fragColor = colSum / colSum.w;
    }
    """

    src_po = """
    ///////////////////Abstract Portal
    /**
    * My first shader - an attempt to create an abstract portal to another dimension!
    *
    * Drawing upon the code described by 'phil' at https://www.shadertoy.com/view/ltBXRc
    **/
    /**
    * Applies smooth displacement to the circumference of the circle.
    **/
    float variation(vec2 v1, vec2 v2, float strength, float speed) {
        return sin(
            dot(normalize(v1), normalize(v2)) * strength + iTime * speed
        ) / 100.;
    }

    /**
    * Draws a circle with smooth variation to its circumference over time. 
    * @rad - the radius of the circle
    * @width - how thick the circle is
    * @index - what circle is currently being drawn? Currently, every odd circle is drawn with opposing displacement for effect
    **/
    vec3 paintCircle (vec2 uv, vec2 center, float rad, float width, float index) {
        vec2 diff = center-uv;
        float len = length(diff);
        float scale = rad;
        float mult = mod(index, 2.) == 0. ? 1. : -1.; 
        len += variation(diff, vec2(rad*mult, 1.0), 7.0*scale, 2.0);
        len -= variation(diff, vec2(1.0, rad*mult), 7.0*scale, 2.0);
        float circle = smoothstep((rad-width)*scale, (rad)*scale, len) - smoothstep((rad)*scale, (rad+width)*scale, len);
        return vec3(circle);
    }

    /**
    * A ring consists of a wider faded circle with an overlaid white solid inner circle. 
    **/
    vec3 paintRing(vec2 uv, vec2 center, float radius, float index){
         //paint color circle
        vec3 color = paintCircle(uv, center, radius, 0.075, index);
        //this is where the blue color is applied - change for different mood
        color *= vec3(0.3,0.85,1.0);
        //paint white circle
        color += paintCircle(uv, center, radius, 0.015, index);
        return color;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        //define our primary 'variables'
        vec2 uv = fragCoord.xy / iResolution.xy;
        const float numRings = 20.;
        const vec2 center = vec2(0.5);
        const float spacing = 1. / numRings;
        const float slow = 30.;
        const float cycleDur = 1.;
        const float tunnelElongation = .25;
        float radius = mod(iTime/slow, cycleDur);
        vec3 color;

        //this provides the smooth fade black border, which we will mix in later
        float border = 0.25;
        vec2 bl = smoothstep(0., border, uv); // bottom left
        vec2 tr = smoothstep(0., border, 1.-uv); // top right
        float edges = bl.x * bl.y * tr.x * tr.y;

        //push in the left and right sides to make the warp square
        uv.x *= 1.5;
        uv.x -= 0.25; 
        
        //do the work
        for(float i=0.; i<numRings; i++){
            color += paintRing(uv, center, tunnelElongation*log(mod(radius + i * spacing, cycleDur)), i ); //these are the fast circles
            color += paintRing(uv, center, log(mod(radius + i * spacing, cycleDur)), i); //these are essentially the same but move at a slower pace
        }

        //combined, these create a black fade around the edges of our screen
        color = mix(color, vec3(0.), 1.-edges); 
        color = mix(color, vec3(0.), distance(uv, center));
        //boom!
        fragColor = vec4(color, 1.0);
    }
    """

    src_jl = """
    ///////////////////Jello Lights

    #define PI 3.141592
    #define ORBS 20.

    void mainImage(out vec4 fragColor, in vec2 fragCoord) {
      vec2 uv = (2. * fragCoord - iResolution.xy) / iResolution.y;
      uv *= 279.27;
      fragColor = vec4(0.);
      for (float i = 0.; i < ORBS; i++) {
        uv.y -= i / 1000. * (uv.x); 
        uv.x += i / 0.05 * sin(uv.x / 9.32 + iTime) * 0.21 * cos(uv.y / 16.92 + iTime / 3.) * 0.21;
        float t = 5.1 * i * PI / float(ORBS) * (2. + 1.) + iTime / 10.;
        float x = -1. * tan(t);
        float y = sin(t / 3.5795); 
        vec2 p = (115. * vec2(x, y)) / sin(PI * sin(uv.x / 14.28 + iTime / 10.));
        vec3 col = cos(vec3(0, 1, -1) * PI * 2. / 3. + PI * (5. + i / 5.)) * 0.5 + 0.5;
        fragColor += vec4(i / 40. * 55.94 / length(uv - p * 0.9) * col, 3.57);
      }
      fragColor.xyz = pow(fragColor.xyz, vec3(3.57));
      fragColor.w = 1.0;
    }
    """

    src_ev = """
    ///////////////////Evil membrane

    // Evil Membrane
    // Another gyroid noise with light and color

    #define R iResolution.xy
    #define N(x,y,z) normalize(vec3(x,y,z))

    float gyroid (vec3 seed)
    {
        return dot(sin(seed),cos(seed.yzx));
    }

    float fbm (vec3 seed)
    {
        float result = 0., a = .5;
        for (int i = 0; i < 6; ++i)
        {
            // extra spicy twist
            seed.z += result*.5;
            
            // bounce it with abs
            result += abs(gyroid(seed/a))*a;
            
            a /= 2.;
        }
        return result;
    }

    float noise (vec2 p)
    {
        // improvise 3d seed from 2d coordinates
        vec3 seed = vec3(p, length(p) - iTime * .1) * 1.;
        
        // make it slide along the sin wave
        return sin(fbm(seed)*6.+iTime)*.5+.5;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        // coordinates
        vec2 p = (2.*fragCoord-R)/R.y;
        
        // noise grayscale
        float shade = noise(p);
        
        // normal gradient
        vec3 normal = normalize(vec3(shade-vec2(noise(p+vec2(.01,0)), noise(p+vec2(0,.01))), .2));
        
        vec3 color = vec3(0.);
        
        // light from above
        color += .5*pow(dot(normal, N(0,1,1))*.5+.5, 10.);
        
        // tinted light
        vec3 tint = .5+.5*cos(vec3(1,2,3)*5.+shade+p.x+normal.y*2.);
        color += tint*.3*pow(dot(normal, N(0,0,1))*.5+.5, 10.);
        
        // pink light from below
        color += .5*vec3(1.000,0.580,0.580)*pow(dot(normal, N(0,-2,1))*.5+.5, 2.);
        
        fragColor = vec4(color*shade, 1);
    }
    """

    src_abp = """
    ///////////////////abstract pattern

    // Inigo Quilez
    // https://iquilezles.org/articles/distfunctions/
    float smin(float d1, float d2, float k)
    {
        float h = clamp( 0.5 + 0.5*(d2-d1)/k, 0.0, 1.0 );
        return mix( d2, d1, h ) - k*h*(1.0-h);
    }

    // Dave Hoskins
    // https://www.shadertoy.com/view/4djSRW
    float hash12(vec2 p)
    {
        vec3 p3  = fract(vec3(p.xyx) * .1031);
        p3 += dot(p3, p3.yzx + 33.33);
        return fract((p3.x + p3.y) * p3.z);
    }

    // Abstract Patterns #6 by Leon Denise 2022/05/09

    // Inspired by Martijn Steinrucken "Math Zoo - Alien Orb"
    // https://www.youtube.com/watch?v=b0AayhCO7s8
    // https://www.shadertoy.com/view/tlcXWX

    // Using code from Martijn Steinrucken, Dave Hoskins,
    // Inigo Quilez, Antoine Zanuttini and many more

    const float scale = 5.;
    const float shell = .3;
    const float carve = .3;
    const float falloff = 1.8;
    const float blend = .02;

    // signed distance function
    float map(vec3 p)
    {
        vec3 pp = p;
        float d = 100.;
        float a = 1.;
        
        // gyroid multi scale pattern
        for (float i = 0.; i < 3.; ++i)
        {
            p = pp * scale / a;
            p.z -= iTime * a;
            d = smin(d, abs(dot(sin(p),cos(p.yzx))/scale*a), blend);
            a /= falloff;
        }
        
        // invert volume
        d = -d;
        
        // ripple surface
        d += sin(p.z*10.+iTime*20.)*0.002;
        
        // substract sphere
        d = smin(d, -(length(pp)-shell), -carve);
        
        return d;
    }

    // NuSan
    // https://www.shadertoy.com/view/3sBGzV
    vec3 getNormal (vec3 pos)
    {
        vec2 noff = vec2(0.001,0);
        return normalize(map(pos)-vec3(map(pos-noff.xyy), map(pos-noff.yxy), map(pos-noff.yyx)));
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        // coordinates
        vec2 uv = (fragCoord.xy - iResolution.xy / 2.)/iResolution.y;
        float dither = hash12(fragCoord);
        vec3 ray = normalize(vec3(uv, -0.5));
        vec3 pos = vec3(0);

        // raymarching
        float index = 0.;
        const float count = 17.;
        for (index = count; index > 0.; --index)
        {
            float dist = map(pos);
            if (dist < .001) break;
            dist *= .9+.1*dither;
            pos += ray*dist;
        }

        // coloring
        vec3 normal = getNormal(pos);
        vec3 color = .5+.2*normal;
        float backLight = dot(normal, vec3(0,0,-1))*.5+.5;
        float bottomLight = dot(normal, vec3(0,-1,0))*.5+.5;
        vec3 tint = .9*cos(vec3(1,2,3)+pos.z*18.-iTime);
        color += vec3(1,-.5,-.5)*backLight;
        color += tint * bottomLight;
        color *= index/count;

        fragColor = vec4(color, 1.);
    }
    """

    src_sr = """
    ///////////////////sun rays

    float rayStrength(vec2 raySource, vec2 rayRefDirection, vec2 coord, float seedA, float seedB, float speed)
    {
        vec2 sourceToCoord = coord - raySource;
        float cosAngle = dot(normalize(sourceToCoord), rayRefDirection);

        return clamp(
            (0.45 + 0.15 * sin(cosAngle * seedA + iTime * speed)) +
            (0.3 + 0.2 * cos(-cosAngle * seedB + iTime * speed)),
            0.0, 1.0) *
            clamp((iResolution.x - length(sourceToCoord)) / iResolution.x, 0.5, 1.0);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord.xy / iResolution.xy;
        uv.y = 1.0 - uv.y;
        vec2 coord = vec2(fragCoord.x, iResolution.y - fragCoord.y);

        // Set the parameters of the sun rays
        vec2 rayPos1 = vec2(iResolution.x * 0.7, iResolution.y * -0.4);
        vec2 rayRefDir1 = normalize(vec2(1.0, -0.116));
        float raySeedA1 = 36.2214;
        float raySeedB1 = 21.11349;
        float raySpeed1 = 1.5;

        vec2 rayPos2 = vec2(iResolution.x * 0.8, iResolution.y * -0.6);
        vec2 rayRefDir2 = normalize(vec2(1.0, 0.241));
        const float raySeedA2 = 22.39910;
        const float raySeedB2 = 18.0234;
        const float raySpeed2 = 1.1;

        // Calculate the colour of the sun rays on the current fragment
        vec4 rays1 =
            vec4(1.0, 1.0, 1.0, 1.0) *
            rayStrength(rayPos1, rayRefDir1, coord, raySeedA1, raySeedB1, raySpeed1);

        vec4 rays2 =
            vec4(1.0, 1.0, 1.0, 1.0) *
            rayStrength(rayPos2, rayRefDir2, coord, raySeedA2, raySeedB2, raySpeed2);

        fragColor = rays1 * 0.5 + rays2 * 0.4;

        // Attenuate brightness towards the bottom, simulating light-loss due to depth.
        // Give the whole thing a blue-green tinge as well.
        float brightness = 1.0 - (coord.y / iResolution.y);
        fragColor.x *= 0.1 + (brightness * 0.8);
        fragColor.y *= 0.3 + (brightness * 0.6);
        fragColor.z *= 0.5 + (brightness * 0.5);
    }
    """

    src_spr= """
    ///////////////////spiral riders

    #define rot(a) mat2(cos(a),sin(a),-sin(a),cos(a))

    vec3 render(vec2 p) {
        p*=rot(iTime*.1)*(.0002+.7*pow(smoothstep(0.,.5,abs(.5-fract(iTime*.01))),3.));
        p.y-=.2266;
        p.x+=.2082;
        vec2 ot=vec2(100.);
        float m=100.;
        for (int i=0; i<150; i++) {
            vec2 cp=vec2(p.x,-p.y);
            p=p+cp/dot(p,p)-vec2(0.,.25);
            p*=.1;
            p*=rot(1.5);
            ot=min(ot,abs(p)+.15*fract(max(abs(p.x),abs(p.y))*.25+iTime*.1+float(i)*.15));
            m=min(m,abs(p.y));
        }
        ot=exp(-200.*ot)*2.;
        m=exp(-200.*m);
        return vec3(ot.x,ot.y*.5+ot.x*.3,ot.y)+m*.2;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord-iResolution.xy*.5)/iResolution.y;
        vec2 d=vec2(0.,.5)/iResolution.xy;
        vec3 col = render(uv)+render(uv+d.xy)+render(uv-d.xy)+render(uv+d.yx)+render(uv-d.yx);
        fragColor = vec4(col*.2,1.0);
    }
    """

    src_im = """
    ///////////////////Inside the Matrix
    /*
      Feel free to do anything you want with this code.
      This shader uses "runes" code by FabriceNeyret2 (https://www.shadertoy.com/view/4ltyDM)
      which is based on "runes" by otaviogood (https://shadertoy.com/view/MsXSRn).
      These random runes look good as matrix symbols and have acceptable performance.
    */

    const int ITERATIONS = 40;   //use less value if you need more performance
    const float SPEED = 1.;

    const float STRIP_CHARS_MIN =  7.;
    const float STRIP_CHARS_MAX = 40.;
    const float STRIP_CHAR_HEIGHT = 0.15;
    const float STRIP_CHAR_WIDTH = 0.10;
    const float ZCELL_SIZE = 1. * (STRIP_CHAR_HEIGHT * STRIP_CHARS_MAX);  //the multiplier can't be less than 1.
    const float XYCELL_SIZE = 12. * STRIP_CHAR_WIDTH;  //the multiplier can't be less than 1.

    const int BLOCK_SIZE = 10;  //in cells
    const int BLOCK_GAP = 2;    //in cells

    const float WALK_SPEED = 1. * XYCELL_SIZE;
    const float BLOCKS_BEFORE_TURN = 3.;

    const float PI = 3.14159265359;

    //        ----  random  ----

    float hash(float v) {
        return fract(sin(v)*43758.5453123);
    }

    float hash(vec2 v) {
        return hash(dot(v, vec2(5.3983, 5.4427)));
    }

    vec2 hash2(vec2 v)
    {
        v = vec2(v * mat2(127.1, 311.7,  269.5, 183.3));
        return fract(sin(v)*43758.5453123);
    }

    vec4 hash4(vec2 v)
    {
        vec4 p = vec4(v * mat4x2( 127.1, 311.7,
                                  269.5, 183.3,
                                  113.5, 271.9,
                                  246.1, 124.6 ));
        return fract(sin(p)*43758.5453123);
    }

    vec4 hash4(vec3 v)
    {
        vec4 p = vec4(v * mat4x3( 127.1, 311.7, 74.7,
                                  269.5, 183.3, 246.1,
                                  113.5, 271.9, 124.6,
                                  271.9, 269.5, 311.7 ) );
        return fract(sin(p)*43758.5453123);
    }
    //        ----  symbols  ----
    //  Slightly modified version of "runes" by FabriceNeyret2 -  https://www.shadertoy.com/view/4ltyDM
    //  Which is based on "runes" by otaviogood -  https://shadertoy.com/view/MsXSRn

    float rune_line(vec2 p, vec2 a, vec2 b) {   // from https://www.shadertoy.com/view/4dcfW8
        p -= a, b -= a;
        float h = clamp(dot(p, b) / dot(b, b), 0., 1.);   // proj coord on line
        return length(p - b * h);                         // dist to segment
    }

    float rune(vec2 U, vec2 seed, float highlight)
    {
        float d = 1e5;
        for (int i = 0; i < 4; i++) // number of strokes
        {
            vec4 pos = hash4(seed);
            seed += 1.;

            // each rune touches the edge of its box on all 4 sides
            if (i == 0) pos.y = .0;
            if (i == 1) pos.x = .999;
            if (i == 2) pos.x = .0;
            if (i == 3) pos.y = .999;
            // snap the random line endpoints to a grid 2x3
            vec4 snaps = vec4(2, 3, 2, 3);
            pos = ( floor(pos * snaps) + .5) / snaps;

            if (pos.xy != pos.zw)  //filter out single points (when start and end are the same)
                d = min(d, rune_line(U, pos.xy, pos.zw + .001) ); // closest line
        }
        return smoothstep(0.1, 0., d) + highlight*smoothstep(0.4, 0., d);
    }

    float random_char(vec2 outer, vec2 inner, float highlight) {
        vec2 seed = vec2(dot(outer, vec2(269.5, 183.3)), dot(outer, vec2(113.5, 271.9)));
        return rune(inner, seed, highlight);
    }

    //        ----  digital rain  ----

    // xy - horizontal, z - vertical
    vec3 rain(vec3 ro3, vec3 rd3, float time) {
        vec4 result = vec4(0.);

        // normalized 2d projection
        vec2 ro2 = vec2(ro3);
        vec2 rd2 = normalize(vec2(rd3));

        // we use formulas `ro3 + rd3 * t3` and `ro2 + rd2 * t2`, `t3_to_t2` is a multiplier to convert t3 to t2
        bool prefer_dx = abs(rd2.x) > abs(rd2.y);
        float t3_to_t2 = prefer_dx ? rd3.x / rd2.x : rd3.y / rd2.y;

        // at first, horizontal space (xy) is divided into cells (which are columns in 3D)
        // then each xy-cell is divided into vertical cells (along z) - each of these cells contains one raindrop

        ivec3 cell_side = ivec3(step(0., rd3));      //for positive rd.x use cell side with higher x (1) as the next side, for negative - with lower x (0), the same for y and z
        ivec3 cell_shift = ivec3(sign(rd3));         //shift to move to the next cell

        //  move through xy-cells in the ray direction
        float t2 = 0.;  // the ray formula is: ro2 + rd2 * t2, where t2 is positive as the ray has a direction.
        ivec2 next_cell = ivec2(floor(ro2/XYCELL_SIZE));  //first cell index where ray origin is located
        for (int i=0; i<ITERATIONS; i++) {
            ivec2 cell = next_cell;  //save cell value before changing
            float t2s = t2;          //and t

            //  find the intersection with the nearest side of the current xy-cell (since we know the direction, we only need to check one vertical side and one horizontal side)
            vec2 side = vec2(next_cell + cell_side.xy) * XYCELL_SIZE;  //side.x is x coord of the y-axis side, side.y - y of the x-axis side
            vec2 t2_side = (side - ro2) / rd2;  // t2_side.x and t2_side.y are two candidates for the next value of t2, we need the nearest
            if (t2_side.x < t2_side.y) {
                t2 = t2_side.x;
                next_cell.x += cell_shift.x;  //cross through the y-axis side
            } else {
                t2 = t2_side.y;
                next_cell.y += cell_shift.y;  //cross through the x-axis side
            }
            //now t2 is the value of the end point in the current cell (and the same point is the start value in the next cell)

            //  gap cells
            vec2 cell_in_block = fract(vec2(cell) / float(BLOCK_SIZE));
            float gap = float(BLOCK_GAP) / float(BLOCK_SIZE);
            if (cell_in_block.x < gap || cell_in_block.y < gap || (cell_in_block.x < (gap+0.1) && cell_in_block.y < (gap+0.1))) {
                continue;
            }

            //  return to 3d - we have start and end points of the ray segment inside the column (t3s and t3e)
            float t3s = t2s / t3_to_t2;

            //  move through z-cells of the current column in the ray direction (don't need much to check, two nearest cells are enough)
            float pos_z = ro3.z + rd3.z * t3s;
            float xycell_hash = hash(vec2(cell));
            float z_shift = xycell_hash*11. - time * (0.5 + xycell_hash * 1.0 + xycell_hash * xycell_hash * 1.0 + pow(xycell_hash, 16.) * 3.0);  //a different z shift for each xy column
            float char_z_shift = floor(z_shift / STRIP_CHAR_HEIGHT);
            z_shift = char_z_shift * STRIP_CHAR_HEIGHT;
            int zcell = int(floor((pos_z - z_shift)/ZCELL_SIZE));  //z-cell index
            for (int j=0; j<2; j++) {  //2 iterations is enough if camera doesn't look much up or down
                //  calcaulate coordinates of the target (raindrop)
                vec4 cell_hash = hash4(vec3(ivec3(cell, zcell)));
                vec4 cell_hash2 = fract(cell_hash * vec4(127.1, 311.7, 271.9, 124.6));

                float chars_count = cell_hash.w * (STRIP_CHARS_MAX - STRIP_CHARS_MIN) + STRIP_CHARS_MIN;
                float target_length = chars_count * STRIP_CHAR_HEIGHT;
                float target_rad = STRIP_CHAR_WIDTH / 2.;
                float target_z = (float(zcell)*ZCELL_SIZE + z_shift) + cell_hash.z * (ZCELL_SIZE - target_length);
                vec2 target = vec2(cell) * XYCELL_SIZE + target_rad + cell_hash.xy * (XYCELL_SIZE - target_rad*2.);

                //  We have a line segment (t0,t). Now calculate the distance between line segment and cell target (it's easier in 2d)
                vec2 s = target - ro2;
                float tmin = dot(s, rd2);  //tmin - point with minimal distance to target
                if (tmin >= t2s && tmin <= t2) {
                    float u = s.x * rd2.y - s.y * rd2.x;  //horizontal coord in the matrix strip
                    if (abs(u) < target_rad) {
                        u = (u/target_rad + 1.) / 2.;
                        float z = ro3.z + rd3.z * tmin/t3_to_t2;
                        float v = (z - target_z) / target_length;  //vertical coord in the matrix strip
                        if (v >= 0.0 && v < 1.0) {
                            float c = floor(v * chars_count);  //symbol index relative to the start of the strip, with addition of char_z_shift it becomes an index relative to the whole cell
                            float q = fract(v * chars_count);
                            vec2 char_hash = hash2(vec2(c+char_z_shift, cell_hash2.x));
                            if (char_hash.x >= 0.1 || c == 0.) {  //10% of missed symbols
                                float time_factor = floor(c == 0. ? time*5.0 :  //first symbol is changed fast
                                        time*(1.0*cell_hash2.z +   //strips are changed sometime with different speed
                                                cell_hash2.w*cell_hash2.w*4.*pow(char_hash.y, 4.)));  //some symbols in some strips are changed relatively often
                                float a = random_char(vec2(char_hash.x, time_factor), vec2(u,q), max(1., 3. - c/2.)*0.2);  //alpha
                                a *= clamp((chars_count - 0.5 - c) / 2., 0., 1.);  //tail fade
                                if (a > 0.) {
                                    float attenuation = 1. + pow(0.06*tmin/t3_to_t2, 2.);
                                    vec3 col = (c == 0. ? vec3(0.67, 1.0, 0.82) : vec3(0.25, 0.80, 0.40)) / attenuation;
                                    float a1 = result.a;
                                    result.a = a1 + (1. - a1) * a;
                                    result.xyz = (result.xyz * a1 + col * (1. - a1) * a) / result.a;
                                    if (result.a > 0.98)  return result.xyz;
                                }
                            }
                        }
                    }
                }
                // not found in this cell - go to next vertical cell
                zcell += cell_shift.z;
            }
            // go to next horizontal cell
        }

        return result.xyz * result.a;
    }

    //        ----  main, camera  ----

    vec2 rotate(vec2 v, float a) {
        float s = sin(a);
        float c = cos(a);
        mat2 m = mat2(c, -s, s, c);
        return m * v;
    }

    vec3 rotateX(vec3 v, float a) {
        float s = sin(a);
        float c = cos(a);
        return mat3(1.,0.,0.,0.,c,-s,0.,s,c) * v;
    }

    vec3 rotateY(vec3 v, float a) {
        float s = sin(a);
        float c = cos(a);
        return mat3(c,0.,-s,0.,1.,0.,s,0.,c) * v;
    }

    vec3 rotateZ(vec3 v, float a) {
        float s = sin(a);
        float c = cos(a);
        return mat3(c,-s,0.,s,c,0.,0.,0.,1.) * v;
    }

    float smoothstep1(float x) {
        return smoothstep(0., 1., x);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        if (STRIP_CHAR_WIDTH > XYCELL_SIZE || STRIP_CHAR_HEIGHT * STRIP_CHARS_MAX > ZCELL_SIZE) {
            // error
            fragColor = vec4(1., 0., 0., 1.);
            return;
        }

        vec2 uv = (fragCoord.xy * 2. - iResolution.xy) / iResolution.y;

        float time = iTime * SPEED;

        const float turn_rad = 0.25 / BLOCKS_BEFORE_TURN;   //0 .. 0.5
        const float turn_abs_time = (PI/2.*turn_rad) * 1.5;  //multiplier different than 1 means a slow down on turns
        const float turn_time = turn_abs_time / (1. - 2.*turn_rad + turn_abs_time);  //0..1, but should be <= 0.5

        float level1_size = float(BLOCK_SIZE) * BLOCKS_BEFORE_TURN * XYCELL_SIZE;
        float level2_size = 4. * level1_size;
        float gap_size = float(BLOCK_GAP) * XYCELL_SIZE;

        vec3 ro = vec3(gap_size/2., gap_size/2., 0.);
        vec3 rd = vec3(uv.x, 2.0, uv.y);

        float tq = fract(time / (level2_size*4.) * WALK_SPEED);  //the whole cycle time counter
        float t8 = fract(tq*4.);  //time counter while walking on one of the four big sides
        float t1 = fract(t8*8.);  //time counter while walking on one of the eight sides of the big side

        vec2 prev;
        vec2 dir;
        if (tq < 0.25) {
            prev = vec2(0.,0.);
            dir = vec2(0.,1.);
        } else if (tq < 0.5) {
            prev = vec2(0.,1.);
            dir = vec2(1.,0.);
        } else if (tq < 0.75) {
            prev = vec2(1.,1.);
            dir = vec2(0.,-1.);
        } else {
            prev = vec2(1.,0.);
            dir = vec2(-1.,0.);
        }
        float angle = floor(tq * 4.);  //0..4 wich means 0..2*PI

        prev *= 4.;

        const float first_turn_look_angle = 0.4;
        const float second_turn_drift_angle = 0.5;
        const float fifth_turn_drift_angle = 0.25;

        vec2 turn;
        float turn_sign = 0.;
        vec2 dirL = rotate(dir, -PI/2.);
        vec2 dirR = -dirL;
        float up_down = 0.;
        float rotate_on_turns = 1.;
        float roll_on_turns = 1.;
        float add_angel = 0.;
        if (t8 < 0.125) {
            turn = dirL;
            //dir = dir;
            turn_sign = -1.;
            angle -= first_turn_look_angle * (max(0., t1 - (1. - turn_time*2.)) / turn_time - max(0., t1 - (1. - turn_time)) / turn_time * 2.5);
            roll_on_turns = 0.;
        } else if (t8 < 0.250) {
            prev += dir;
            turn = dir;
            dir = dirL;
            angle -= 1.;
            turn_sign = 1.;
            add_angel += first_turn_look_angle*0.5 + (-first_turn_look_angle*0.5+1.0+second_turn_drift_angle)*t1;
            rotate_on_turns = 0.;
            roll_on_turns = 0.;
        } else if (t8 < 0.375) {
            prev += dir + dirL;
            turn = dirR;
            //dir = dir;
            turn_sign = 1.;
            add_angel += second_turn_drift_angle*sqrt(1.-t1);
            //roll_on_turns = 0.;
        } else if (t8 < 0.5) {
            prev += dir + dir + dirL;
            turn = dirR;
            dir = dirR;
            angle += 1.;
            turn_sign = 0.;
            up_down = sin(t1*PI) * 0.37;
        } else if (t8 < 0.625) {
            prev += dir + dir;
            turn = dir;
            dir = dirR;
            angle += 1.;
            turn_sign = -1.;
            up_down = sin(-min(1., t1/(1.-turn_time))*PI) * 0.37;
        } else if (t8 < 0.750) {
            prev += dir + dir + dirR;
            turn = dirL;
            //dir = dir;
            turn_sign = -1.;
            add_angel -= (fifth_turn_drift_angle + 1.) * smoothstep1(t1);
            rotate_on_turns = 0.;
            roll_on_turns = 0.;
        } else if (t8 < 0.875) {
            prev += dir + dir + dir + dirR;
            turn = dir;
            dir = dirL;
            angle -= 1.;
            turn_sign = 1.;
            add_angel -= fifth_turn_drift_angle - smoothstep1(t1) * (fifth_turn_drift_angle * 2. + 1.);
            rotate_on_turns = 0.;
            roll_on_turns = 0.;
        } else {
            prev += dir + dir + dir;
            turn = dirR;
            //dir = dir;
            turn_sign = 1.;
            angle += fifth_turn_drift_angle * (1.5*min(1., (1.-t1)/turn_time) - 0.5*smoothstep1(1. - min(1.,t1/(1.-turn_time))));
        }

        if (iMouse.x > 10. || iMouse.y > 10.) {
            vec2 mouse = iMouse.xy / iResolution.xy * 2. - 1.;
            up_down = -0.7 * mouse.y;
            angle += mouse.x;
            rotate_on_turns = 1.;
            roll_on_turns = 0.;
        } else {
            angle += add_angel;
        }

        rd = rotateX(rd, up_down);

        vec2 p;
        if (turn_sign == 0.) {
            //  move forward
            p = prev + dir * (turn_rad + 1. * t1);
        }
        else if (t1 > (1. - turn_time)) {
            //  turn
            float tr = (t1 - (1. - turn_time)) / turn_time;
            vec2 c = prev + dir * (1. - turn_rad) + turn * turn_rad;
            p = c + turn_rad * rotate(dir, (tr - 1.) * turn_sign * PI/2.);
            angle += tr * turn_sign * rotate_on_turns;
            rd = rotateY(rd, sin(tr*turn_sign*PI) * 0.2 * roll_on_turns);  //roll
        }  else  {
            //  move forward
            t1 /= (1. - turn_time);
            p = prev + dir * (turn_rad + (1. - turn_rad*2.) * t1);
        }

        rd = rotateZ(rd, angle * PI/2.);

        ro.xy += level1_size * p;

        ro += rd * 0.2;
        rd = normalize(rd);

        vec3 col = rain(ro, rd, time);

        fragColor = vec4(col, 1.);
    }
    """

    src_plp = """
    /////////////////// Plexus Particles

    float distLine(vec2 p, vec2 a, vec2 b) {
        vec2 ap = p - a;
        vec2 ab = b - a;
        float aDotB = clamp(dot(ap, ab) / dot(ab, ab), 0.0, 1.0);
        return length(ap - ab * aDotB);
    }

    float drawLine(vec2 uv, vec2 a, vec2 b) {
        float line = smoothstep(0.014, 0.01, distLine(uv, a, b));
        float dist = length(b-a);
        return line * (smoothstep(1.3, 0.8, dist) * 0.5 + smoothstep(0.04, 0.03, abs(dist - 0.75)));
    }

    float n21(vec2 i) {
        i += fract(i * vec2(223.64, 823.12));
        i += dot(i, i + 23.14);
        return fract(i.x * i.y);
    }

    vec2 n22(vec2 i) {
        float x = n21(i);
        return vec2(x, n21(i+x));
    }

    vec2 getPoint (vec2 id, vec2 offset) {
        return offset + sin(n22(id + offset) * iTime * 1.0) * 0.4;
    }

    float layer (vec2 uv) {
        float m = 0.0;
        float t = iTime * 2.0;
       
        vec2 gv = fract(uv) - 0.5;
        vec2 id = floor(uv) - 0.5;
        
        vec2 p[9];
        int i = 0;
        for (float y = -1.0; y <= 1.0; y++) {
            for (float x = -1.0; x <= 1.0; x++) {
                p[i++] = getPoint(id, vec2(x,y));
            }
        }
        
        for (int i = 0; i < 9; i++) {
            m += drawLine(gv, p[4], p[i]);
            float sparkle = 1.0 / pow(length(gv - p[i]), 1.5) * 0.005;
            m += sparkle * (sin(t + fract(p[i].x) * 12.23) * 0.4 + 0.6);
        }
        
        m += drawLine(gv, p[1], p[3]);
        m += drawLine(gv, p[1], p[5]);
        m += drawLine(gv, p[7], p[3]);
        m += drawLine(gv, p[7], p[5]);
         
        return m;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord - 0.5 * iResolution.xy) / iResolution.y;
        vec3 c = sin(iTime * 2.0 * vec3(.234, .324,.768)) * 0.4 + 0.6;
        vec3 col = vec3(0);
        float fft = texelFetch(iChannel0, ivec2(76.0, 0.), 0).x / 2.0 + 0.5;
        c.x += (uv.x + 0.5);
        col += pow(-uv.y + 0.5, 5.0) * fft * c;
        
        float m = 0.0;
        float x = sin(iTime * 0.1);
        float y = cos(iTime * 0.2);
        
        mat2 rotMat = mat2(x, y, -y, x);
        uv *= rotMat;
        
        for (float i = 0.0; i <= 1.0; i+= 1.0/4.0) {
            float z = fract(i + iTime * 0.05);
            float size = mix(15.0, .1, z) * 1.50;
            float fade = smoothstep(0.0, 1.0,  z) * smoothstep(1.0, 0.9, z);
            m += layer((size * uv) + i * 10.0 ) * fade;
        }
        
        col += m * c;
        // Debug
        fragColor = vec4(col,1.0);
    }
    """

    src_w95 = """
    ///////////////////Windows 95

    #ifdef GL_ES
    precision mediump float;
    #endif

    #define PI 3.1415926535897932384626433832795

    const float wave_amplitude = 0.076;
    const float period = 2.*PI;

    float wave_phase() {
        return iTime;
    }

    float square(vec2 st) {
        vec2 bl = step(vec2(0.), st);       // bottom-left
        vec2 tr = step(vec2(0.),1.0-st);   // top-right
        return bl.x * bl.y * tr.x * tr.y;
    }

    vec4 frame(vec2 st) {
        float tushka = square(st*mat2((1./.48), 0., 0., (1./.69)));
        
        mat2 sector_mat = mat2(1./.16, 0., 0., 1./.22);
        float sectors[4];
        sectors[0] = square(st * sector_mat + (1./.16)*vec2(0.000,-0.280));
        sectors[1] = square(st * sector_mat + (1./.16)*vec2(0.000,-0.060));
        sectors[2] = square(st * sector_mat + (1./.16)*vec2(-0.240,-0.280));
        sectors[3] = square(st * sector_mat + (1./.16)*vec2(-0.240,-0.060));
        vec3 sector_colors[4];
        sector_colors[0] = vec3(0.941, 0.439, 0.404) * sectors[0];
        sector_colors[1] = vec3(0.435, 0.682, 0.843) * sectors[1];
        sector_colors[2] = vec3(0.659, 0.808, 0.506) * sectors[2];
        sector_colors[3] = vec3(0.996, 0.859, 0.114) * sectors[3];
        
        return vec4(vec3(sector_colors[0] + sector_colors[1] +
                         sector_colors[2] + sector_colors[3]), tushka);
    }

    vec4 trail_piece(vec2 st, vec2 index, float scale) {
        scale = index.x * 0.082 + 0.452;
        
        vec3 color;
        if (index.y > 0.9 && index.y < 2.1 ) {
            color = vec3(0.435, 0.682, 0.843);
            scale *= .8;
        } else if (index.y > 3.9 && index.y < 5.1) {
            color = vec3(0.941, 0.439, 0.404);
            scale *= .8;
        } else {
            color = vec3(0., 0., 0.);
        }
        
        float scale1 = 1./scale;
        float shift = - (1.-scale) / (2. * scale);
        vec2 st2 = vec2(vec3(st, 1.) * mat3(scale1, 0., shift, 0., scale1, shift, 0., 0., 1.));
        float mask = square(st2);

        return vec4( color, mask );
    }

    vec4 trail(vec2 st) {
        // actually 1/width, 1/height
        const float piece_height = 7. / .69;
        const float piece_width = 6. / .54;
      
        // make distance between smaller segments slightly lower
        st.x = 1.2760 * pow(st.x, 3.0) - 1.4624 * st.x*st.x + 1.4154 * st.x;
        
        float x_at_cell = floor(st.x*piece_width)/piece_width;
        float x_at_cell_center = x_at_cell + 0.016;
        float incline = cos(0.5*period + wave_phase()) * wave_amplitude;
        
        float offset = sin(x_at_cell_center*period + wave_phase())* wave_amplitude + 
            incline*(st.x-x_at_cell)*5.452;
        
        float mask = step(offset, st.y) * (1.-step(.69+offset, st.y)) * step(0., st.x);
        
        vec2 cell_coord = vec2((st.x - x_at_cell) * piece_width,
                               fract((st.y-offset) * piece_height));
        vec2 cell_index = vec2(x_at_cell * piece_width, 
                               floor((st.y-offset) * piece_height));
        
        vec4 pieces = trail_piece(cell_coord, cell_index, 0.752);
        
        return vec4(vec3(pieces), pieces.a * mask);
    }

    vec4 logo(vec2 st) {
        if (st.x <= .54) {
            return trail(st);
        } else {
            vec2 st2 = st + vec2(0., -sin(st.x*period + wave_phase())*wave_amplitude);
            return frame(st2 + vec2(-.54, 0));
        }
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
        vec2 st = fragCoord.xy/iResolution.xy;
        st.x *= iResolution.x/iResolution.y;

        st += vec2(.0);
        st *= 1.472;
        st += vec2(-0.7,-0.68);
        float rot = PI*-0.124;
        st *= mat2(cos(rot), sin(rot), -sin(rot), cos(rot));
        vec3 color = vec3(1.);
        
        vec4 logo_ = logo(st);    
        fragColor = mix(vec4(0.,.5,.5,1.000), logo_, logo_.a);
    }
    """

    src_sc_3d = """
    /////////////////// sincos 3d

    #define A(v) mat2(cos(m.v+radians(vec4(0, -90, 90, 0))))  // rotate
    #define W(v) length(vec3(p.yz-v(p.x+vec2(0, pi_2)+t), 0))-lt  // wave
    //#define W(v) length(p-vec3(round(p.x*pi)/pi, v(t+p.x), v(t+pi_2+p.x)))-lt  // wave
    #define P(v) length(p-vec3(0, v(t), v(t+pi_2)))-pt  // point
    void mainImage( out vec4 C, in vec2 U )
    {
        float lt = .1, // line thickness
              pt = .3, // point thickness
              pi = 3.1416,
              pi2 = pi*2.,
              pi_2 = pi/2.,
              t = iTime*pi/10,
              s = 1., d = 0., i = d;
        vec2 R = iResolution.xy,
             m = vec2(0, 0); //for rotate m = (iMouse.xy-.5*R)/R.y*4.;
        vec3 o = vec3(0, 0, -7), // cam
             u = normalize(vec3((U-.5*R)/R.y, 1)),
             c = vec3(0), k = c, p;
        if (iMouse.z < 1.) m = -vec2(t/20.-pi_2, 0);
        mat2 v = A(y), h = A(x); // pitch & yaw
        for (; i++<50.;) // raymarch
        {
            p = o+u*d;
            p.yz *= v;
            p.xz *= h;
            p.x -= 3.;
            if (p.y < -1.5) p.y = 2./p.y;
            k.x = min( max(p.x+lt, W(sin)), P(sin) );
            k.y = min( max(p.x+lt, W(cos)), P(cos) );
            s = min(s, min(k.x, k.y));
            if (s < .001 || d > 100.) break;
            d += s*.5;
        }
        c = max(cos(d*pi2) - s*sqrt(d) - k, 0.);
        c.gb += .1;
        C = vec4(c*.4 + c.brg*.6 + c*c, 1);
    }
    """

    src_boot = """
    /////////////////// Boot

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord-iResolution.xy*0.5)/iResolution.y*2.0;
        
        float a = atan(uv.y, uv.x);
        float l = length(uv);

        float x = 48.0*(l-0.3+sin(iTime)*0.06125);
        float c = abs(cos(x*2.0)/x)*max(0.0,(1.75-abs(x*0.001*(0.5*sin(iTime)*0.5))));
        float d = 0.0;
        float t = iTime*0.75;
        d += sin(a*1.0+t*0.5);
        d += sin(a*2.0-t*1.2);
        d += sin(a*3.0+t*1.5);
        d += sin(a*2.0-t*1.7);
        d += sin(a*1.0+t*3.8);
        float amount = c*d;
        vec3 col = vec3(0.2,0.8,1.0)*(0.05+amount*0.3);
        fragColor = vec4(col,1.0);
    }
    """

src_cm = """
/////////////////////
// Luminescence by Martijn Steinrucken aka BigWings - 2017
// Email:countfrolic@gmail.com Twitter:@The_ArtOfCode
// License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
// My entry for the monthly challenge (May 2017) on r/proceduralgeneration 
// Use the mouse to look around. Uncomment the SINGLE define to see one specimen by itself.
// Code is a bit of a mess, too lazy to clean up. Hope you like it!
// Music by Klaus Lunde
// https://soundcloud.com/klauslunde/zebra-tribute
// YouTube: The Art of Code -> https://www.youtube.com/channel/UCcAlTqd9zID6aNX3TzwxJXg
// Twitter: @The_ArtOfCode

#define INVERTMOUSE -1.

#define MAX_STEPS 100.
#define VOLUME_STEPS 8.
//#define SINGLE
#define MIN_DISTANCE 0.1
#define MAX_DISTANCE 100.
#define HIT_DISTANCE .01

#define S(x,y,z) smoothstep(x,y,z)
#define B(x,y,z,w) S(x-z, x+z, w)*S(y+z, y-z, w)
#define sat(x) clamp(x,0.,1.)
#define SIN(x) sin(x)*.5+.5

const vec3 lf=vec3(1., 0., 0.);
const vec3 up=vec3(0., 1., 0.);
const vec3 fw=vec3(0., 0., 1.);

const float halfpi = 1.570796326794896619;
const float pi = 3.141592653589793238;
const float twopi = 6.283185307179586;

vec3 accentColor1 = vec3(1., .1, .5);
vec3 secondColor1 = vec3(.1, .5, 1.);

vec3 accentColor2 = vec3(1., .5, .1);
vec3 secondColor2 = vec3(.1, .5, .6);

vec3 bg;        // global background color
vec3 accent;    // color of the phosphorecence

float N1( float x ) { return fract(sin(x)*5346.1764); }
float N2(float x, float y) { return N1(x + y*23414.324); }

float N3(vec3 p) {
    p  = fract( p*0.3183099+.1 );
    p *= 17.0;
    return fract( p.x*p.y*p.z*(p.x+p.y+p.z) );
}

struct ray {
    vec3 o;
    vec3 d;
};

struct camera {
    vec3 p;         // the position of the camera
    vec3 forward;   // the camera forward vector
    vec3 left;      // the camera left vector
    vec3 up;        // the camera up vector

    vec3 center;    // the center of the screen, in world coords
    vec3 i;         // where the current ray intersects the screen, in world coords
    ray ray;        // the current ray: from cam pos, through current uv projected on screen
    vec3 lookAt;    // the lookat point
    float zoom;     // the zoom factor
};

struct de {
    // data type used to pass the various bits of information used to shade a de object
    float d;    // final distance to field
    float m;    // material
    vec3 uv;
    float pump;
    
    vec3 id;
    vec3 pos;       // the world-space coordinate of the fragment
};

struct rc {
    // data type used to handle a repeated coordinate
    vec3 id;    // holds the floor'ed coordinate of each cell. Used to identify the cell.
    vec3 h;     // half of the size of the cell
    vec3 p;     // the repeated coordinate
    //vec3 c;   // the center of the cell, world coordinates
};

rc Repeat(vec3 pos, vec3 size) {
    rc o;
    o.h = size*.5;
    o.id = floor(pos/size);         // used to give a unique id to each cell
    o.p = mod(pos, size)-o.h;
    //o.c = o.id*size+o.h;

    return o;
}

camera cam;

void CameraSetup(vec2 uv, vec3 position, vec3 lookAt, float zoom) {

    cam.p = position;
    cam.lookAt = lookAt;
    cam.forward = normalize(cam.lookAt-cam.p);
    cam.left = cross(up, cam.forward);
    cam.up = cross(cam.forward, cam.left);
    cam.zoom = zoom;

    cam.center = cam.p+cam.forward*cam.zoom;
    cam.i = cam.center+cam.left*uv.x+cam.up*uv.y;

    cam.ray.o = cam.p;                   // ray origin = camera position
    cam.ray.d = normalize(cam.i-cam.p); // ray direction is the vector from the cam pos through the point on the imaginary screen
}

// ============== Functions I borrowed ;)

//  3 out, 1 in... DAVE HOSKINS
vec3 N31(float p) {
   vec3 p3 = fract(vec3(p) * vec3(.1031,.11369,.13787));
   p3 += dot(p3, p3.yzx + 19.19);
   return fract(vec3((p3.x + p3.y)*p3.z, (p3.x+p3.z)*p3.y, (p3.y+p3.z)*p3.x));
}

// DE functions from IQ
float smin( float a, float b, float k )
{
    float h = clamp( 0.5+0.5*(b-a)/k, 0.0, 1.0 );
    return mix( b, a, h ) - k*h*(1.0-h);
}

float smax( float a, float b, float k )
{
    float h = clamp( 0.5 + 0.5*(b-a)/k, 0.0, 1.0 );
    return mix( a, b, h ) + k*h*(1.0-h);
}

float sdSphere( vec3 p, vec3 pos, float s ) { return (length(p-pos)-s); }

// From http://mercury.sexy/hg_sdf
vec2 pModPolar(inout vec2 p, float repetitions, float fix) {
    float angle = twopi/repetitions;
    float a = atan(p.y, p.x) + angle/2.;
    float r = length(p);
    float c = floor(a/angle);
    a = mod(a,angle) - (angle/2.)*fix;
    p = vec2(cos(a), sin(a))*r;

    return p;
}

// -------------------------

float Dist( vec2 P,  vec2 P0, vec2 P1 ) {
    //2d point-line distance
    
    vec2 v = P1 - P0;
    vec2 w = P - P0;

    float c1 = dot(w, v);
    float c2 = dot(v, v);
    
    if (c1 <= 0. )  // before P0
        return length(P-P0);
    
    float b = c1 / c2;
    vec2 Pb = P0 + b*v;
    return length(P-Pb);
}

vec3 ClosestPoint(vec3 ro, vec3 rd, vec3 p) {
    // returns the closest point on ray r to point p
    return ro + max(0., dot(p-ro, rd))*rd;
}

vec2 RayRayTs(vec3 ro1, vec3 rd1, vec3 ro2, vec3 rd2) {
    // returns the two t's for the closest point between two rays
    // ro+rd*t1 = ro2+rd2*t2
    
    vec3 dO = ro2-ro1;
    vec3 cD = cross(rd1, rd2);
    float v = dot(cD, cD);
    
    float t1 = dot(cross(dO, rd2), cD)/v;
    float t2 = dot(cross(dO, rd1), cD)/v;
    return vec2(t1, t2);
}

float DistRaySegment(vec3 ro, vec3 rd, vec3 p1, vec3 p2) {
    // returns the distance from ray r to line segment p1-p2
    vec3 rd2 = p2-p1;
    vec2 t = RayRayTs(ro, rd, p1, rd2);

    t.x = max(t.x, 0.);
    t.y = clamp(t.y, 0., length(rd2));

    vec3 rp = ro+rd*t.x;
    vec3 sp = p1+rd2*t.y;

    return length(rp-sp);
}

vec2 sph(vec3 ro, vec3 rd, vec3 pos, float radius) {
    // does a ray sphere intersection
    // returns a vec2 with distance to both intersections
    // if both a and b are MAX_DISTANCE then there is no intersection

    vec3 oc = pos - ro;
    float l = dot(rd, oc);
    float det = l*l - dot(oc, oc) + radius*radius;
    if (det < 0.0) return vec2(MAX_DISTANCE);

    float d = sqrt(det);
    float a = l - d;
    float b = l + d;

    return vec2(a, b);
}

vec3 background(vec3 r) {

    float x = atan(r.x, r.z);       // from -pi to pi   
    float y = pi*0.5-acos(r.y);     // from -1/2pi to 1/2pi     

    vec3 col = bg*(1.+y);

    float t = iTime;                // add god rays

    float a = sin(r.x);

    float beam = sat(sin(10.*x+a*y*5.+t));
    beam *= sat(sin(7.*x+a*y*3.5-t));

    float beam2 = sat(sin(42.*x+a*y*21.-t));
    beam2 *= sat(sin(34.*x+a*y*17.+t));

    beam += beam2;
    col *= 1.+beam*.05;

    return col;
}

float remap(float a, float b, float c, float d, float t) {
    return ((t-a)/(b-a))*(d-c)+c;
}

de map( vec3 p, vec3 id ) {

    float t = iTime*2.;

    float N = N3(id);

    de o;
    o.m = 0.;

    float x = (p.y+N*twopi)*1.+t;
    float r = 1.;

    float pump = cos(x+cos(x))+sin(2.*x)*.2+sin(4.*x)*.02;

    x = t + N*twopi;
    p.y -= (cos(x+cos(x))+sin(2.*x)*.2)*.6;
    p.xz *= 1. + pump*.2;
    
    float d1 = sdSphere(p, vec3(0., 0., 0.), r);
    float d2 = sdSphere(p, vec3(0., -.5, 0.), r);

    o.d = smax(d1, -d2, .1);
    o.m = 1.;

    if(p.y<.5) {
        float sway = sin(t+p.y+N*twopi)*S(.5, -3., p.y)*N*.3;
        p.x += sway*N;  // add some sway to the tentacles
        p.z += sway*(1.-N);

        vec3 mp = p;
        mp.xz = pModPolar(mp.xz, 6., 0.);

        float d3 = length(mp.xz-vec2(.2, .1))-remap(.5, -3.5, .1, .01, mp.y);
        if(d3<o.d) o.m=2.;
        d3 += (sin(mp.y*10.)+sin(mp.y*23.))*.03;

        float d32 = length(mp.xz-vec2(.2, .1))-remap(.5, -3.5, .1, .04, mp.y)*.5;
        d3 = min(d3, d32);
        o.d = smin(o.d, d3, .5);

        if( p.y<.2) {
             vec3 op = p;
        op.xz = pModPolar(op.xz, 13., 1.);

            float d4 = length(op.xz-vec2(.85, .0))-remap(.5, -3., .04, .0, op.y);
            if(d4<o.d) o.m=3.;
            o.d = smin(o.d, d4, .15);
        }
    }
    o.pump = pump;
    o.uv = p;

    o.d *= .8;
    return o;
}

vec3 calcNormal( de o ) {
    vec3 eps = vec3( 0.01, 0.0, 0.0 );
    vec3 nor = vec3(
        map(o.pos+eps.xyy, o.id).d - map(o.pos-eps.xyy, o.id).d,
        map(o.pos+eps.yxy, o.id).d - map(o.pos-eps.yxy, o.id).d,
        map(o.pos+eps.yyx, o.id).d - map(o.pos-eps.yyx, o.id).d );
    return normalize(nor);
}

de CastRay(ray r) {
    float d = 0.;
    float dS = MAX_DISTANCE;

    vec3 pos = vec3(0., 0., 0.);
    vec3 n = vec3(0.);
    de o, s;

    float dC = MAX_DISTANCE;
    vec3 p;
    rc q;
    float t = iTime;
    vec3 grid = vec3(6., 30., 6.);

    for(float i=0.; i<MAX_STEPS; i++) {
        p = r.o + r.d*d;

        #ifdef SINGLE
        s = map(p, vec3(0.));
        #else
        p.y -= t;  // make the move up
        p.x += t;  // make cam fly forward

        q = Repeat(p, grid);

        vec3 rC = ((2.*step(0., r.d)-1.)*q.h-q.p)/r.d;  // ray to cell boundary
        dC = min(min(rC.x, rC.y), rC.z)+.01;        // distance to cell just past boundary

        float N = N3(q.id);
        q.p += (N31(N)-.5)*grid*vec3(.5, .7, .5);

        if(Dist(q.p.xz, r.d.xz, vec2(0.))<1.1)
        //if(DistRaySegment(q.p, r.d, vec3(0., -6., 0.), vec3(0., -3.3, 0)) <1.1) 
            s = map(q.p, q.id);
        else
            s.d = dC;

        #endif

        if(s.d<HIT_DISTANCE || d>MAX_DISTANCE) break;
        d+=min(s.d, dC);    // move to distance to next cell or surface, whichever is closest
    }

    if(s.d<HIT_DISTANCE) {
        o.m = s.m;
        o.d = d;
        o.id = q.id;
        o.uv = s.uv;
        o.pump = s.pump;

        #ifdef SINGLE
        o.pos = p;
        #else
        o.pos = q.p;
        #endif
    }

    return o;
}

float VolTex(vec3 uv, vec3 p, float scale, float pump) {
    // uv = the surface pos
    // p = the volume shell pos

    p.y *= scale;

    float s2 = 5.*p.x/twopi;
    float id = floor(s2);
    s2 = fract(s2);
    vec2 ep = vec2(s2-.5, p.y-.6);
    float ed = length(ep);
    float e = B(.35, .45, .05, ed);

    float s = SIN(s2*twopi*15. );
    s = s*s; s = s*s;
    s *= S(1.4, -.3, uv.y-cos(s2*twopi)*.2+.3)*S(-.6, -.3, uv.y);

    float t = iTime*5.;
    float mask = SIN(p.x*twopi*2. + t);
    s *= mask*mask*2.;

    return s+e*pump*2.;
}

vec4 JellyTex(vec3 p) { 
    vec3 s = vec3(atan(p.x, p.z), length(p.xz), p.y);

    float b = .75+sin(s.x*6.)*.25;
    b = mix(1., b, s.y*s.y);

    p.x += sin(s.z*10.)*.1;
    float b2 = cos(s.x*26.) - s.z-.7;

    b2 = S(.1, .6, b2);
    return vec4(b+b2);
}

vec3 render( vec2 uv, ray camRay, float depth ) {
    // outputs a color
    
    bg = background(cam.ray.d);
    
    vec3 col = bg;
    de o = CastRay(camRay);
    
    float t = iTime;
    vec3 L = up;
    

    if(o.m>0.) {
        vec3 n = calcNormal(o);
        float lambert = sat(dot(n, L));
        vec3 R = reflect(camRay.d, n);
        float fresnel = sat(1.+dot(camRay.d, n));
        float trans = (1.-fresnel)*.5;
        vec3 ref = background(R);
        float fade = 0.;
        
        if(o.m==1.) {   // hood color
            float density = 0.;
            for(float i=0.; i<VOLUME_STEPS; i++) {
                float sd = sph(o.uv, camRay.d, vec3(0.), .8+i*.015).x;
                if(sd!=MAX_DISTANCE) {
                    vec2 intersect = o.uv.xz+camRay.d.xz*sd;

                    vec3 uv = vec3(atan(intersect.x, intersect.y), length(intersect.xy), o.uv.z);
                    density += VolTex(o.uv, uv, 1.4+i*.03, o.pump);
                }
            }
            vec4 volTex = vec4(accent, density/VOLUME_STEPS); 
            
            
            vec3 dif = JellyTex(o.uv).rgb;
            dif *= max(.2, lambert);

            col = mix(col, volTex.rgb, volTex.a);
            col = mix(col, vec3(dif), .25);

            col += fresnel*ref*sat(dot(up, n));

            //fade
            fade = max(fade, S(.0, 1., fresnel));
        } else if(o.m==2.) {                        // inside tentacles
            vec3 dif = accent;
            col = mix(bg, dif, fresnel);

            col *= mix(.6, 1., S(0., -1.5, o.uv.y));

            float prop = o.pump+.25;
            prop *= prop*prop;
            col += pow(1.-fresnel, 20.)*dif*prop;

            fade = fresnel;
        } else if(o.m==3.) {                        // outside tentacles
            vec3 dif = accent;
            float d = S(100., 13., o.d);
            col = mix(bg, dif, pow(1.-fresnel, 5.)*d);
        }

        fade = max(fade, S(0., 100., o.d));
        col = mix(col, bg, fade);

        if(o.m==4.)
            col = vec3(1., 0., 0.);
    }
     else
        col = bg;

    return col;
}

void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    float t = iTime*.04;

    vec2 uv = (fragCoord.xy / iResolution.xy);
    uv -= .5;
    uv.y *= iResolution.y/iResolution.x; 

    vec2 m = iMouse.xy/iResolution.xy;

    if(m.x<0.05 || m.x>.95) {               // move cam automatically when mouse is not used
        m = vec2(t*.25, SIN(t*pi)*.5+.5);
    }

    accent = mix(accentColor1, accentColor2, SIN(t*15.456));
    bg = mix(secondColor1, secondColor2, SIN(t*7.345231));

    float turn = (.1-m.x)*twopi;
    float s = sin(turn);
    float c = cos(turn);
    mat3 rotX = mat3(c,  0., s, 0., 1., 0., s,  0., -c);

    #ifdef SINGLE
    float camDist = -10.;
    #else
    float camDist = -.1;
    #endif

    vec3 lookAt = vec3(0., -1., 0.);

    vec3 camPos = vec3(0., INVERTMOUSE*camDist*cos((m.y)*pi), camDist)*rotX;

    CameraSetup(uv, camPos+lookAt, lookAt, 1.);

    vec3 col = render(uv, cam.ray, 0.);

    col = pow(col, vec3(mix(1.5, 2.6, SIN(t+pi))));     // post-processing
    float d = 1.-dot(uv, uv);       // vignette
    col *= (d*d*d)+.1;

    fragColor = vec4(col, 1.);
}
"""

src_ft = """
////////////////// Fire Tornado

const float tol = .31;
vec3 ro;

const float an = .001;
const float cw = cos(an);
const float sw = sin(an);

mat2 rot(float an) { float cc=cos(an),ss=sin(an); return mat2(cc,ss,-ss,cc); }

float wheel(vec3 p) {
    
    
    vec4 q = vec4(p , 15. );  
    
    
    vec4 jc = q; 
    
    float ww = 9.;
    
    
    float i=0.;
    float scale = 1.27;
    
    for (;i<11.;i++){
        
        if ( q.x > 1. )  q.x = 2. - q.x;
        else if ( q.x < -1.) q.x = -2. - q.x;
        
        if ( q.y > 1. )  q.y = 2. - q.y;
        else if ( q.y < -1.) q.y = -2. - q.y;
        
        if ( q.z > 1. )  q.z = 2. - q.z;
        else if ( q.z < -1.) q.z = -2. - q.z;
        
        if ( q.w > 1. )  q.w = 2. - q.w;
        else if ( q.w < -1.) q.w = -2. - q.w;
        
        float lz1 = length(q.xyz);

        float lzz1;
        
        float tt=iTime/4.;

        if ( lz1 < .66 ) { q.xyz *= 4.; ww *= 4.; q.xy = rot( tt )*q.xy; }
        else if ( lz1 < 1.6) { q.xyz = q.xyz/(lzz1=lz1*lz1); ww *= lzz1; q.xy = rot(-tt)*q.xy; }

        q = scale * q + jc/2.;
        ww *= scale;
    }
    return (length(q))/ ww;
}

vec2 scene(vec3 p) {
    return vec2(  max( wheel(p), -(length(p-ro)-1.48 ) ) ,  1.);
}

vec3 gradient(vec3 p) {
    vec2 dpn = vec2(1.,-1.);
    vec2 dp  = 1e-4 * dpn; 
    vec3 df = dpn.xxx * scene(p+dp.xxx).x +
              dpn.yyx * scene(p+dp.yyx).x +
              dpn.xyy * scene(p+dp.xyy).x +
              dpn.yxy * scene(p+dp.yxy).x;

    return normalize(df); 
}

vec3 march( vec3 ro, vec3 rd) {
    float dist = 1e6,  totDist=0.,  distFac=1.;
    vec3 p = ro;
    vec3 color = vec3(0);
    for (float i=0.; i<10.; i++) {
        dist = scene(p).x;
        //if  (  dist < tol * distFac )  { return exp(-totDist/2.)*vec3(dot(gradient(p),rd)); }
        p += dist * rd;
        totDist += dist;
        //distFac *= (1.+totDist*60.);
        color += vec3( dist, dist*dist/2.,0.) * exp(-totDist/i);
    }
    return color; 
}

void mainImage0( out vec4 O, in vec2 U )
{
    U = (2.*U - iResolution.xy) / iResolution.y *2.;
    vec3 rd = normalize( vec3(U, 5.) );
    //rd.xz = rot(iTime/5.)*rd.xz;
    ro = vec3(0.,0., -3.98); //-3.8 + .3*sin(iTime/2.) );
    vec3 color = march( ro, rd );
    //if ( length(U) > 2.2) color=vec3(0.);
    O = vec4( pow(color,vec3(.5)), 1);
}

//thanks Faabrice
void mainImage(out vec4 O, vec2 U) {
    mainImage0(O,U);
    if ( fwidth(length(O)) > .01 ) {  // difference threshold between neighbor pixels
        vec4 o;
        for (int k=0; k < 9; k+= k==3?2:1 )
          { mainImage0(o,U+vec2(k%3-1,k/3-1)/3.); O += o; }
        O /= 9.;
      //O.r++;                        // uncomment to see where the oversampling occurs
    }
}
"""

fragment_src_w8 = """
/////////////////// Windows 8 style loader

const float PI = 3.14159265359;
float interpolateLinear(float a, float b, float t){
  return mix(a, b, clamp(t, 0.0, 1.0));
}
float interpolateEaseOut(float a, float b, float t){
  return mix(a, b, clamp(sin(clamp(t, 0.0, 1.0) * (PI * 0.5)), 0.0, 1.0));
}
float interpolateEaseInOut(float a, float b, float t){
  return mix(a, b, clamp((cos((clamp(t, 0.0, 1.0) * PI) + PI) + 1.0) * 0.5, 0.0, 1.0));
}
vec2 rotate(vec2 v, float a){
    return vec2((v.x*cos(a))-(v.y*sin(a)), (v.x*sin(a))+(v.y*cos(a)));
}
float t2;
float line(vec2 p1, vec2 p2, vec2 p, float t){
    vec2 a = p - p1, b = p2 - p1;
    a = rotate(a, -atan(b.y, b.x));
    return pow(clamp(t / ((a.x < 0.0) ? length(a) : ((a.x < length(b)) ? abs(a.y) : length(p - p2))), 0.0, 1.0), t2);
}
void mainImage( out vec4 fragColor, in vec2 fragCoord ){
  vec4 c = vec4(vec3(0.0), 1.0);
  vec2 p = (((fragCoord.xy / iResolution.xy) - vec2(0.5)) * 2.0) * vec2(1., iResolution.y / iResolution.x);
    vec2 cp = (p + vec2(0.0, 0.3275)) * 32.0;  
  float t = mod(iTime, 5.5);
  vec4 ec0 = vec4(43.0 / 255.0, 128.0 / 255.0, 255.0 / 255.0, 1.0);
  vec4 ec1 = vec4(1.0);
  vec2 pp = p - vec2(0.0, 0.125);
  {
    vec2 cp = (pp * 4.0) + vec2(0., 0.0);
    cp.y *= 1.65;
    cp.x += 0.005;
    cp.y -= 0.3875;
    float d = dot(cp, normalize(vec2(-0.5, -0.5))) + 0.5;
    d = min(d, dot(cp, normalize(vec2(0.5, -0.5))) + 0.5);
    d = min(d, dot(cp, normalize(vec2(0.5, 0.0))) + 0.5);
    d = min(d, dot(cp, normalize(vec2(-0.5, 0.0))) + 0.5);
    cp.y += 0.5;
    d = min(d, dot(cp, normalize(vec2(0.5, 0.5))) + 0.5);
    d = min(d, dot(cp, normalize(vec2(-0.5, 0.5))) + 0.5);
        c = ec0 * clamp(d * 64.0, 0.0, 1.0); 
  }
  {
    vec2 cp = (pp * 1.5) + vec2(0.43, -0.29);
    vec2 ip = vec2(0.5, -0.5) / vec2(80.0, 80.0);
    float envelope1 = clamp(texture(iChannel0, vec2(0., 0.25)).x, 0.0, 1.0);
    float g = interpolateEaseInOut(0.002, 0.005, envelope1);
    t2 = interpolateEaseInOut(4.0, 1.25, envelope1);  
        c = mix(c, ec1, clamp(line(vec2(69., 69.) * ip, vec2(72., 67.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(72., 67.) * ip, vec2(72., 64.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(72., 64.) * ip, vec2(69., 62.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(69., 62.) * ip, vec2(66., 64.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(66., 64.) * ip, vec2(66., 67.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(66., 67.) * ip, vec2(69., 69.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(69., 62.) * ip, vec2(69., 59.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(69., 59.) * ip, vec2(73., 57.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(73., 57.) * ip, vec2(60., 48.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(60., 48.) * ip, vec2(63., 45.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(63., 45.) * ip, vec2(78., 54.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(78., 54.) * ip, vec2(83., 51.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(83., 51.) * ip, vec2(69., 43.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(69., 43.) * ip, vec2(73., 40.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(73., 40.) * ip, vec2(84., 47.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(84., 47.) * ip, vec2(84., 41.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(84., 41.) * ip, vec2(78., 37.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(78., 37.) * ip, vec2(84., 33.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(84., 33.) * ip, vec2(84., 37.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(69., 59.) * ip, vec2(52., 50.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(52., 50.) * ip, vec2(49., 52.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(82., 51.) * ip, vec2(86., 52.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(86., 52.) * ip, vec2(89., 50.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(89., 50.) * ip, vec2(90., 50.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(90., 50.) * ip, vec2(92., 52.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(92., 52.) * ip, vec2(92., 56.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(92., 56.) * ip, vec2(90., 58.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(90., 58.) * ip, vec2(89., 58.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(89., 58.) * ip, vec2(86., 56.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(86., 56.) * ip, vec2(86., 52.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(96., 57.) * ip, vec2(96., 26.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(96., 26.) * ip, vec2(68.5, 10.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(68.5, 10.) * ip, vec2(41., 26.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(41., 26.) * ip, vec2(41., 57.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(41., 57.) * ip, vec2(68.5, 73.) * ip, cp, g), 0.0, 1.0)); 
        c = mix(c, ec1, clamp(line(vec2(68.5, 73.) * ip, vec2(96.0, 57.0) * ip, cp, g), 0.0, 1.0)); 
  }
  for(int i = 0; i < 5; i++){
      float ct = max(0.0, t - (float(i) * 0.24));
      float cca = interpolateEaseInOut(225.0, 345.0, ct / 0.385);
      cca = interpolateLinear(cca, 455.0, (ct - 0.385) / 1.265);
      cca = interpolateEaseOut(cca, 690.0, (ct - 1.65) / 1.495);
      cca = interpolateLinear(cca, 815.0, (ct - 2.149) / 1.705);
      cca = (interpolateEaseOut(cca, 945.0, (ct - 3.85) / 0.275) * (PI / 180.0)) - (PI * 0.25);
    c = mix(c, vec4(1.0), clamp(pow(1.0 - smoothstep(0., 1., length((vec2(sin(cca), cos(cca)) * 1.0) - cp) * 3.0), 8.0) * 2.0, 0.0, 1.0) * 
                              interpolateEaseOut(interpolateEaseOut(0.0, 1.0, (ct - 0.0) / 0.055), 0.0, (ct - 4.125) / 0.055));
    } 
    fragColor=c;
}
"""

fragment_src_w11 = """
/////////////////// Windows 11

//==========Configration==========//
#define PI 3.14159265
//#define Surface_Logo

float scale        = 1.0;
float anim_speed   = 0.7;
float aa_level     = 1.375;
float r_small_rate = 1.0 / 6.0;
//==========Configration==========//

vec2 GetClipCoord(in vec2 coord, in vec2 ar)
{
    coord = (coord / iResolution.xy) * 2.0 - 1.0;
    return coord * ar;
}

float sdBox(in vec2 p, in float b)
{
    vec2 d = abs(p) - b;
    return length(max(d,0.0)) + min(max(d.x,d.y),0.0);
}

float sdCircle(in vec2 p, in float r)
{
    return length(p) - r;
}

float sdLogo(in vec2 p)
{
    float width_rate = 0.975;
    float b = width_rate * 0.5;
    vec2  c = vec2(b + (1.0 - width_rate));
    
    return sdBox(abs(p) - c, b);
}

vec3 Logo(in vec2 p, in float aa_width, out float t_logo)
{
#ifdef Surface_Logo
    vec3 col      = vec3(1.0);
#else
    vec3 base_col = vec3(0.0, 0.2, 1.0);
    vec3 col      = base_col * max(sqrt(p.y + 1.375), 0.001);
#endif

    t_logo = sdLogo(p);
    t_logo = 1.0 - smoothstep(-aa_width, aa_width, t_logo);
    col *= t_logo;
    
    return col;
}

float SpinningCircle(in vec2 p, in float aa_width)
{
    // Animation speed
    float time = iTime * anim_speed;

    // Get radius data
    float r_big   = 1.0 / (r_small_rate + 1.0);
    float r_small = r_big * r_small_rate;

    // Ring
    float t_ring = abs(sdCircle(p, r_big)) - r_small;
          t_ring = 1.0 - smoothstep(-aa_width, aa_width, t_ring);
    
    // Circles
    vec2  a = vec2(4.0 / 5.0, 5.0 / 4.0);
          a = (pow(vec2(mod(time, 3.0) / 3.0), a) * 3.0) * PI * 2.0;
    vec2  p_cir_1 = vec2(sin(a.x), cos(a.x)) * r_big;
    vec2  p_cir_2 = vec2(sin(a.y), cos(a.y)) * r_big;

    float t_cir =     sdCircle(p_cir_1 - p, r_small);
          t_cir = min(sdCircle(p_cir_2 - p, r_small), t_cir);
          t_cir = 1.0 - smoothstep(-aa_width, aa_width, t_cir);

    vec2  p_dir = normalize(p);
    float is_right_dir = step(0.0, p_dir.x) * 2.0 - 1.0;

    float a_uv  = acos(p_dir.y * is_right_dir);
          a_uv += step(is_right_dir, 0.0) * PI;
    vec2  a_floor = floor(a / (PI * 2.0));

    vec2 b_uv = a_uv + a_floor * PI * 2.0;
         b_uv = step(vec2(0.0), min(b_uv - a.y, a.x - b_uv));
    t_cir = min(1.0, max(b_uv.x, b_uv.y) + t_cir) * t_ring;
    
    return t_cir;
}

void mainImage(out vec4 fragColor, in vec2 fragCoord)
{
    // Coordinate
    vec2 ar = max(iResolution.xy / iResolution.yx, vec2(1.0));
    vec2 uv = GetClipCoord(fragCoord, ar) / scale;

    vec3 col = vec3(0.0);
    float aa_width = scale * aa_level / min(iResolution.x, iResolution.y);

    float t_logo;
    vec2 p_logo = (uv - vec2(0.0, 0.25)) * 7.0;
    vec3 logo_col = Logo(p_logo, aa_width * 7.0, t_logo);
    
    vec2 p_sp_cir = (uv + vec2(0.0, 0.5)) * 22.0;
    float t_sp_cir = SpinningCircle(p_sp_cir, aa_width * 22.0);
    col = mix(logo_col, vec3(1.0), t_sp_cir);

    // Output to screen
    col = pow(col, vec3(1.0 / 2.2));
    fragColor = vec4(col, 1.0);
}
"""

src_ms = """
///////////////////  Miracle Snowflakes
//
/* Panteleymonov Aleksandr Konstantinovich 2015
//
// if i write this string my code will be 0 chars, :) */

#define iterations 15.0
#define depth 0.0125
#define layers 8.0
#define layersblob 20
#define step 1.0
#define far 10000.0

float radius=0.25; // radius of Snowflakes. maximum for this demo 0.25.
float zoom=4.0; // use this to change details. optimal 0.1 - 4.0.

vec3 light=vec3(0.0,0.0,1.0);
vec2 seed=vec2(0.0,0.0);
float iteratorc=iterations;
float powr;
float res;

vec4 NC0=vec4(0.0,157.0,113.0,270.0);
vec4 NC1=vec4(1.0,158.0,114.0,271.0);

lowp vec4 hash4( mediump vec4 n ) { return fract(sin(n)*1399763.5453123); }
lowp float noise2( mediump vec2 x )
{
    vec2 p = floor(x);
    lowp vec2 f = fract(x);
    f = f*f*(3.0-2.0*f);
    float n = p.x + p.y*157.0;
    lowp vec4 h = hash4(vec4(n)+vec4(NC0.xy,NC1.xy));
    lowp vec2 s1 = mix(h.xy,h.zw,f.xx);
    return mix(s1.x,s1.y,f.y);
}

lowp float noise222( mediump vec2 x, mediump vec2 y, mediump vec2 z )
{
    mediump vec4 lx = vec4(x*y.x,x*y.y);
    mediump vec4 p = floor(lx);
    lowp vec4 f = fract(lx);
    f = f*f*(3.0-2.0*f);
    mediump vec2 n = p.xz + p.yw*157.0;
    lowp vec4 h = mix(hash4(n.xxyy+NC0.xyxy),hash4(n.xxyy+NC1.xyxy),f.xxzz);
    return dot(mix(h.xz,h.yw,f.yw),z);
}

lowp float noise3( mediump vec3 x )
{
    mediump vec3 p = floor(x);
    lowp vec3 f = fract(x);
    f = f*f*(3.0-2.0*f);
    mediump float n = p.x + dot(p.yz,vec2(157.0,113.0));
    lowp vec4 s1 = mix(hash4(vec4(n)+NC0),hash4(vec4(n)+NC1),f.xxxx);
    return mix(mix(s1.x,s1.y,f.y),mix(s1.z,s1.w,f.y),f.z);
}
lowp vec2 noise3_2( mediump vec3 x ) { return vec2(noise3(x),noise3(x+100.0)); }

float map(mediump vec2 rad)
{
    float a;
    if (res<0.0015) {
        //a = noise2(rad.xy*20.6)*0.9+noise2(rad.xy*100.6)*0.1;
        a = noise222(rad.xy,vec2(20.6,100.6),vec2(0.9,0.1));
    } else if (res<0.005) {
        //float a1 = mix(noise2(rad.xy*10.6),1.0,l);
        //a = texture(iChannel0,rad*0.3).x;
        a = noise2(rad.xy*20.6);
        //if (a1<a) a=a1;
    } else a = noise2(rad.xy*10.3);
    return (a-0.5);
}

vec3 distObj(vec3 pos,vec3 ray,float r,vec2 seed)
{   
    mediump float rq = r*r;
    mediump vec3 dist = ray*far;

    mediump vec3 norm = vec3(0.0,0.0,1.0);
    mediump float invn = 1.0/dot(norm,ray);
    mediump float depthi = depth;
    if (invn<0.0) depthi =- depthi;
    mediump float ds = 2.0*depthi*invn;
    mediump vec3 r1 = ray*(dot(norm,pos)-depthi)*invn-pos;
    mediump vec3 op1 = r1+norm*depthi;
    mediump float len1 = dot(op1,op1);
    mediump vec3 r2 = r1+ray*ds;
    mediump vec3 op2 = r2-norm*depthi;
    mediump float len2 = dot(op2,op2);

    mediump vec3 n = normalize(cross(ray,norm));
    mediump float mind = dot(pos,n);
    mediump vec3 n2 = cross(ray,n);
    mediump float d = dot(n2,pos)/dot(n2,norm);
    mediump float invd = 0.2/depth;
    
    if ((len1<rq || len2<rq) || (abs(mind)<r && d<=depth && d>=-depth))
    {
        mediump vec3 r3 = r2;
        mediump float len = len1;
        if (len>=rq) {
            mediump vec3 n3 = cross(norm,n);
            mediump float a = inversesqrt(rq-mind*mind)*abs(dot(ray,n3));
            mediump vec3 dt = ray/a;
            r1 =- d*norm-mind*n-dt;
            if (len2>=rq) {
                r2 =- d*norm-mind*n+dt;
            }
            ds = dot(r2-r1,ray);
        }
        ds = (abs(ds)+0.1)/(iterations);
        ds = mix(depth,ds,0.2);
        if (ds>0.01) ds=0.01;
        mediump float ir = 0.35/r;
        r *= zoom;
        ray = ray*ds*5.0;
        for (float m=0.0; m<iterations; m+=1.0) {
            if (m>=iteratorc) break;
            mediump float l = length(r1.xy); //inversesqrt(dot(r1.xy,r1.xy));
            lowp vec2 c3 = abs(r1.xy/l);
            if (c3.x>0.5) c3=abs(c3*0.5+vec2(-c3.y,c3.x)*0.86602540);
            mediump float g = l+c3.x*c3.x; //*1.047197551;
            l *= zoom;
            mediump float h = l-r-0.1;
            l = pow(l,powr)+0.1;
            h = max(h,mix(map(c3*l+seed),1.0,abs(r1.z*invd)))+g*ir-0.245; //0.7*0.35=0.245 //*0.911890636
            if ((h<res*20.0) || abs(r1.z)>depth+0.01) break;
            r1 += ray*h;
            ray*=0.99;
        }
        if (abs(r1.z)<depth+0.01) dist=r1+pos;
    }
    return dist;
}

vec3 nray;
vec3 nray1;
vec3 nray2;
float mxc=1.0;

vec4 filterFlake(vec4 color,vec3 pos,vec3 ray,vec3 ray1,vec3 ray2)
{
    vec3 d=distObj(pos,ray,radius,seed);
    vec3 n1=distObj(pos,ray1,radius,seed);
    vec3 n2=distObj(pos,ray2,radius,seed);

    vec3 lq=vec3(dot(d,d),dot(n1,n1),dot(n2,n2));
    if (lq.x<far || lq.y<far || lq.z<far) {
        vec3 n=normalize(cross(n1-d,n2-d));
        if (lq.x<far && lq.y<far && lq.z<far) {
            nray = n;//normalize(nray+n);
            //nray1 = normalize(ray1+n);
            //nray2 = normalize(ray2+n);
        }
        float da = pow(abs(dot(n,light)),3.0);
        vec3 cf = mix(vec3(0.0,0.4,1.0),color.xyz*10.0,abs(dot(n,ray)));
        cf=mix(cf,vec3(2.0),da);
        color.xyz = mix(color.xyz,cf,mxc*mxc*(0.5+abs(dot(n,ray))*0.5));
    }
    
    return color;
}

void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    float time = iTime*0.2;//*0.1;
    res = 1.0 / iResolution.y;
    vec2 p = (-iResolution.xy + 2.0*fragCoord.xy) *res;

    vec3 rotate;
    
    mat3 mr;
    
    vec3 ray = normalize(vec3(p,2.0));
    vec3 ray1;
    vec3 ray2;
    vec3 pos = vec3(0.0,0.0,1.0);

    fragColor = vec4(0.0,0.0,0.0,0.0);
    
    nray = vec3(0.0);
    nray1 = vec3(0.0);
    nray2 = vec3(0.0);
    
    vec4 refcolor=vec4(0.0);
    iteratorc=iterations-layers;
    
    vec2 addrot = vec2(0.0);
    if (iMouse.z>0.0) addrot=(iMouse.xy-iResolution.xy*0.5)*res;
    
    float mxcl = 1.0;
    vec3 addpos=vec3(0.0);
    pos.z = 1.0;
    mxc=1.0;
    radius = 0.25;
    float mzd=(zoom-0.1)/layers;
    for (int i=0; i<layersblob;i++) {
        vec2 p2 = p-vec2(0.25)+vec2(0.1*float(i));
        ray = vec3(p2,2.0)-nray*2.0;
        //ray = nray;//*0.6;
        ray1 = normalize(ray+vec3(0.0,res*2.0,0.0));
        ray2 = normalize(ray+vec3(res*2.0,0.0,0.0));
        ray = normalize(ray);
        vec2 sb = ray.xy*length(pos)/dot(normalize(pos),ray)+vec2(0.0,time);
        seed=floor((sb+vec2(0.0,pos.z)))+pos.z;
        vec3 seedn = vec3(seed,pos.z);
        sb = floor(sb);
        if (noise3(seedn)>0.2 && i<int(layers)) {
            powr = noise3(seedn*10.0)*1.9+0.1;
            rotate.xy=sin((0.5-noise3_2(seedn))*time*5.0)*0.3+addrot;
            rotate.z = (0.5-noise3(seedn+vec3(10.0,3.0,1.0)))*time*5.0;
            seedn.z += time*0.5;
            addpos.xy = sb+vec2(0.25,0.25-time)+noise3_2(seedn)*0.5;
            vec3 sins = sin(rotate);
            vec3 coss = cos(rotate);
            mr=mat3(vec3(coss.x,0.0,sins.x),vec3(0.0,1.0,0.0),vec3(-sins.x,0.0,coss.x));
            mr=mat3(vec3(1.0,0.0,0.0),vec3(0.0,coss.y,sins.y),vec3(0.0,-sins.y,coss.y))*mr;
            mr=mat3(vec3(coss.z,sins.z,0.0),vec3(-sins.z,coss.z,0.0),vec3(0.0,0.0,1.0))*mr;

            light = normalize(vec3(1.0,0.0,1.0))*mr;
            //vec4 cc=filterFlake(fragColor,(pos+addpos)*mr,normalize(ray*mr+nray*0.1),normalize(ray1*mr+nray*0.1),normalize(ray2*mr+nray*0.1));
            vec4 cc = filterFlake(fragColor,(pos+addpos)*mr,ray*mr,ray1*mr,ray2*mr);
            //if (i>0 && dot(nray,nray)!=0.0 && dot(nray1,nray1)!=0.0 && dot(nray2,nray2)!=0.0) refcolor=filterFlake(refcolor,(pos+addpos)*mr,nray,nray1,nray2);
            //cc+=refcolor*0.5;
            fragColor=mix(cc,fragColor,min(1.0,fragColor.w));
        }
        seedn = vec3(sb,pos.z)+vec3(0.5,1000.0,300.0);
        if (noise3(seedn*10.0)>0.4) {
            float raf = 0.3+noise3(seedn*100.0);
            addpos.xy = sb+vec2(0.2,0.2-time)+noise3_2(seedn*100.0)*0.6;
            float l = length(ray*dot(ray,pos+addpos)-pos-addpos);
            l = max(0.0,(1.0-l*10.0*raf));
            fragColor.xyzw += vec4(1.0,1.2,3.0,1.0)*pow(l,5.0)*(pow(0.6+raf,2.0)-0.6)*mxcl;
        }
        mxc -= 1.1/layers;
        pos.z += step;
        iteratorc += 2.0;
        mxcl -= 1.1/float(layersblob);
        zoom-= mzd;
    }
    
    vec3 cr = mix(vec3(0.0),vec3(0.0,0.0,0.4),(-0.55+p.y)*2.0);
    fragColor.xyz += mix((cr.xyz-fragColor.xyz)*0.1,vec3(0.2,0.5,1.0),clamp((-p.y+1.0)*0.5,0.0,1.0));
    
    fragColor = min( vec4(1.0), fragColor );
    fragColor.a = 1.0;
}
"""

src_cl = """
/////////////////// cube lines
// Created by Danil (2021+) https://cohost.org/arugl
// License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
// self https://www.shadertoy.com/view/NslGRN
// --defines for "DESKTOP WALLPAPERS" that use this shader--
// comment or uncomment every define to make it work (add or remove "//" before #define)
// this shadertoy use ALPHA, NO_ALPHA set alpha to 1, BG_ALPHA set background as alpha
// iChannel0 used as background if alpha ignored by wallpaper-app
//#define NO_ALPHA
//#define BG_ALPHA
//#define SHADOW_ALPHA
//#define ONLY_BOX
// save PERFORMANCE by disabling shadow
//#define NO_SHADOW
// static CAMERA position, 0.49 on top, 0.001 horizontal
//#define CAMERA_POS 0.049
// speed of ROTATION

#define ROTATION_SPEED 0.8999

// static SHAPE form, default 0.5
//#define STATIC_SHAPE 0.15
// static SCALE far/close to camera, 2.0 is default, exampe 0.5 or 10.0
//#define CAMERA_FAR 0.1
// ANIMATION shape change
//#define ANIM_SHAPE
// ANIMATION color change
//#define ANIM_COLOR
// custom COLOR, and change those const values
//#define USE_COLOR

const vec3 color_blue=vec3(0.5,0.65,0.8);
const vec3 color_red=vec3(0.99,0.2,0.1);

// use 4xMSAA for cube only (set 2-4-etc level os MSAA)
//#define AA_CUBE 4
// --shader code--
// Layers sorted and support transparency and self-intersection-transparency
// Antialiasing is only dFd. (with some dFd fixes around edges)
// using iq's intersectors: https://iquilezles.org/articles/intersectors
// using https://www.shadertoy.com/view/ltKBzG
// using https://www.shadertoy.com/view/tsVXzh
// using https://www.shadertoy.com/view/WlffDn
// using https://www.shadertoy.com/view/WslGz4

#define tshift 53.

// reflect back side
//#define backside_refl

// Camera with mouse
#define MOUSE_control

// min(iFrame,0) does not speedup compilation in ANGLE
#define ANGLE_loops 0

// this shader discover Nvidia bug with arrays https://www.shadertoy.com/view/NslGR4
// use DEBUG with BUG, BUG trigger that bug and one layer will be white on Nvidia in OpenGL
//#define DEBUG
//#define BUG

#define FDIST 0.7
#define PI 3.1415926
#define GROUNDSPACING 0.5
#define GROUNDGRID 0.05
#define BOXDIMS vec3(0.75, 0.75, 1.25)

#define IOR 1.33

mat3 rotx(float a){float s = sin(a);float c = cos(a);return mat3(vec3(1.0, 0.0, 0.0), vec3(0.0, c, s), vec3(0.0, -s, c));  }
mat3 roty(float a){float s = sin(a);float c = cos(a);return mat3(vec3(c, 0.0, s), vec3(0.0, 1.0, 0.0), vec3(-s, 0.0, c));}
mat3 rotz(float a){float s = sin(a);float c = cos(a);return mat3(vec3(c, s, 0.0), vec3(-s, c, 0.0), vec3(0.0, 0.0, 1.0 ));}

vec3 fcos(vec3 x) {
    vec3 w = fwidth(x);
    //if((length(w)==0.))return vec3(0.); // dFd fix2
    //w*=0.; //test
    float lw=length(w);
    if((lw==0.)||isnan(lw)||isinf(lw)){vec3 tc=vec3(0.); for(int i=0;i<8;i++)tc+=cos(x+x*float(i-4)*(0.01*400./iResolution.y));return tc/8.;}
    
    return cos(x) * smoothstep(3.14 * 2.0, 0.0, w);
}

// rename to fcos
vec3 fcos2( vec3 x){return cos(x);}

vec3 getColor(vec3 p)
{
    // dFd fix, dFd broken on borders, but it fix only top level dFd, self intersection has border
    //if (length(p) > 0.99)return vec3(0.);
    p = abs(p);

    p *= 01.25;
    p = 0.5 * p / dot(p, p);
#ifdef ANIM_COLOR
    p+=0.072*iTime;
#endif

    float t = (0.13) * length(p);
    vec3 col = vec3(0.3, 0.4, 0.5);
    col += 0.12 * fcos(6.28318 * t * 1.0 + vec3(0.0, 0.8, 1.1));
    col += 0.11 * fcos(6.28318 * t * 3.1 + vec3(0.3, 0.4, 0.1));
    col += 0.10 * fcos(6.28318 * t * 5.1 + vec3(0.1, 0.7, 1.1));
    col += 0.10 * fcos(6.28318 * t * 17.1 + vec3(0.2, 0.6, 0.7));
    col += 0.10 * fcos(6.28318 * t * 31.1 + vec3(0.1, 0.6, 0.7));
    col += 0.10 * fcos(6.28318 * t * 65.1 + vec3(0.0, 0.5, 0.8));
    col += 0.10 * fcos(6.28318 * t * 115.1 + vec3(0.1, 0.4, 0.7));
    col += 0.10 * fcos(6.28318 * t * 265.1 + vec3(1.1, 1.4, 2.7));
    col = clamp(col, 0., 1.);
 
    return col;
}

void calcColor(vec3 ro, vec3 rd, vec3 nor, float d, float len, int idx, bool si, float td, out vec4 colx,
               out vec4 colsi)
{

    vec3 pos = (ro + rd * d);
#ifdef DEBUG
    float a = 1. - smoothstep(len - 0.15, len + 0.00001, length(pos));
    if (idx == 0)colx = vec4(1., 0., 0., a);
    if (idx == 1)colx = vec4(0., 1., 0., a);
    if (idx == 2)colx = vec4(0., 0., 1., a);
    if (si)
    {
        pos = (ro + rd * td);
        float ta = 1. - smoothstep(len - 0.15, len + 0.00001, length(pos));
        if (idx == 0)colsi = vec4(1., 0., 0., ta);
        if (idx == 1)colsi = vec4(0., 1., 0., ta);
        if (idx == 2)colsi = vec4(0., 0., 1., ta);
    }
#else
    float a = 1. - smoothstep(len - 0.15*0.5, len + 0.00001, length(pos));
    //a=1.;
    vec3 col = getColor(pos);
    colx = vec4(col, a);
    if (si)
    {
        pos = (ro + rd * td);
        float ta = 1. - smoothstep(len - 0.15*0.5, len + 0.00001, length(pos));
        //ta=1.;
        col = getColor(pos);
        colsi = vec4(col, ta);
    }
#endif
}

// xSI is self intersect data, fade to fix dFd on edges
bool iBilinearPatch(in vec3 ro, in vec3 rd, in vec4 ps, in vec4 ph, in float sz, out float t, out vec3 norm,
                    out bool si, out float tsi, out vec3 normsi, out float fade, out float fadesi)
{
    vec3 va = vec3(0.0, 0.0, ph.x + ph.w - ph.y - ph.z);
    vec3 vb = vec3(0.0, ps.w - ps.y, ph.z - ph.x);
    vec3 vc = vec3(ps.z - ps.x, 0.0, ph.y - ph.x);
    vec3 vd = vec3(ps.xy, ph.x);
    t = -1.;
    tsi = -1.;
    si = false;
    fade = 1.;
    fadesi = 1.;
    norm=vec3(0.,1.,0.);normsi=vec3(0.,1.,0.);

    float tmp = 1.0 / (vb.y * vc.x);
    float a = 0.0;
    float b = 0.0;
    float c = 0.0;
    float d = va.z * tmp;
    float e = 0.0;
    float f = 0.0;
    float g = (vc.z * vb.y - vd.y * va.z) * tmp;
    float h = (vb.z * vc.x - va.z * vd.x) * tmp;
    float i = -1.0;
    float j = (vd.x * vd.y * va.z + vd.z * vb.y * vc.x) * tmp - (vd.y * vb.z * vc.x + vd.x * vc.z * vb.y) * tmp;

    float p = dot(vec3(a, b, c), rd.xzy * rd.xzy) + dot(vec3(d, e, f), rd.xzy * rd.zyx);
    float q = dot(vec3(2.0, 2.0, 2.0) * ro.xzy * rd.xyz, vec3(a, b, c)) + dot(ro.xzz * rd.zxy, vec3(d, d, e)) +
              dot(ro.yyx * rd.zxy, vec3(e, f, f)) + dot(vec3(g, h, i), rd.xzy);
    float r =
        dot(vec3(a, b, c), ro.xzy * ro.xzy) + dot(vec3(d, e, f), ro.xzy * ro.zyx) + dot(vec3(g, h, i), ro.xzy) + j;

    if (abs(p) < 0.000001)
    {
        float tt = -r / q;
        if (tt <= 0.)
            return false;
        t = tt;
        // normal

        vec3 pos = ro + t * rd;
        if(length(pos)>sz)return false;
        vec3 grad =
            vec3(2.0) * pos.xzy * vec3(a, b, c) + pos.zxz * vec3(d, d, e) + pos.yyx * vec3(f, e, f) + vec3(g, h, i);
        norm = -normalize(grad);
        return true;
    }
    else
    {
        float sq = q * q - 4.0 * p * r;
        if (sq < 0.0)
        {
            return false;
        }
        else
        {
            float s = sqrt(sq);
            float t0 = (-q + s) / (2.0 * p);
            float t1 = (-q - s) / (2.0 * p);
            float tt1 = min(t0 < 0.0 ? t1 : t0, t1 < 0.0 ? t0 : t1);
            float tt2 = max(t0 > 0.0 ? t1 : t0, t1 > 0.0 ? t0 : t1);
            float tt0 = tt1;
            if (tt0 <= 0.)
                return false;
            vec3 pos = ro + tt0 * rd;
            // black border on end of circle and self intersection with alpha come because dFd
            // uncomment this to see or rename fcos2 to fcos
            //sz+=0.3; 
            bool ru = step(sz, length(pos)) > 0.5;
            if (ru)
            {
                tt0 = tt2;
                pos = ro + tt0 * rd;
            }
            if (tt0 <= 0.)
                return false;
            bool ru2 = step(sz, length(pos)) > 0.5;
            if (ru2)
                return false;

            // self intersect
            if ((tt2 > 0.) && ((!ru)) && !(step(sz, length(ro + tt2 * rd)) > 0.5))
            {
                si = true;
                fadesi=s;
                tsi = tt2;
                vec3 tpos = ro + tsi * rd;
                // normal
                vec3 tgrad = vec3(2.0) * tpos.xzy * vec3(a, b, c) + tpos.zxz * vec3(d, d, e) +
                             tpos.yyx * vec3(f, e, f) + vec3(g, h, i);
                normsi = -normalize(tgrad);
            }
            
            fade=s;
            t = tt0;
            // normal
            vec3 grad =
                vec3(2.0) * pos.xzy * vec3(a, b, c) + pos.zxz * vec3(d, d, e) + pos.yyx * vec3(f, e, f) + vec3(g, h, i);
            norm = -normalize(grad);

            return true;
        }
    }
}

float dot2( in vec3 v ) { return dot(v,v); }

float segShadow( in vec3 ro, in vec3 rd, in vec3 pa, float sh )
{
    float dm = dot(rd.yz,rd.yz);
    float k1 = (ro.x-pa.x)*dm;
    float k2 = (ro.x+pa.x)*dm;
    vec2  k5 = (ro.yz+pa.yz)*dm;
    float k3 = dot(ro.yz+pa.yz,rd.yz);
    vec2  k4 = (pa.yz+pa.yz)*rd.yz;
    vec2  k6 = (pa.yz+pa.yz)*dm;
    
    for( int i=0; i<4 + ANGLE_loops; i++ )
    {
        vec2  s = vec2(i&1,i>>1);
        float t = dot(s,k4) - k3;
        
        if( t>0.0 )
        sh = min(sh,dot2(vec3(clamp(-rd.x*t,k1,k2),k5-k6*s)+rd*t)/(t*t));
    }
    return sh;
}

float boxSoftShadow( in vec3 ro, in vec3 rd, in vec3 rad, in float sk ) 
{
    rd += 0.0001 * (1.0 - abs(sign(rd)));
    vec3 rdd = rd;
    vec3 roo = ro;

    vec3 m = 1.0/rdd;
    vec3 n = m*roo;
    vec3 k = abs(m)*rad;

    vec3 t1 = -n - k;
    vec3 t2 = -n + k;

    float tN = max( max( t1.x, t1.y ), t1.z );
    float tF = min( min( t2.x, t2.y ), t2.z );

    if( tN<tF && tF>0.0) return 0.0;
    
    float sh = 1.0;
    sh = segShadow( roo.xyz, rdd.xyz, rad.xyz, sh );
    sh = segShadow( roo.yzx, rdd.yzx, rad.yzx, sh );
    sh = segShadow( roo.zxy, rdd.zxy, rad.zxy, sh );
    sh = clamp(sk*sqrt(sh),0.0,1.0);
    return sh*sh*(3.0-2.0*sh);
}

float box(in vec3 ro, in vec3 rd, in vec3 r, out vec3 nn, bool entering)
{
    rd += 0.0001 * (1.0 - abs(sign(rd)));
    vec3 dr = 1.0 / rd;
    vec3 n = ro * dr;
    vec3 k = r * abs(dr);

    vec3 pin = -k - n;
    vec3 pout = k - n;
    float tin = max(pin.x, max(pin.y, pin.z));
    float tout = min(pout.x, min(pout.y, pout.z));
    if (tin > tout)
        return -1.;
    if (entering)
    {
        nn = -sign(rd) * step(pin.zxy, pin.xyz) * step(pin.yzx, pin.xyz);
    }
    else
    {
        nn = sign(rd) * step(pout.xyz, pout.zxy) * step(pout.xyz, pout.yzx);
    }
    return entering ? tin : tout;
}

vec3 bgcol(in vec3 rd)
{
    return mix(vec3(0.01), vec3(0.336, 0.458, .668), 1. - pow(abs(rd.z+0.25), 1.3));
}

vec3 background(in vec3 ro, in vec3 rd , vec3 l_dir, out float alpha)
{
#ifdef ONLY_BOX
alpha=0.;
return vec3(0.01);
#endif
    float t = (-BOXDIMS.z - ro.z) / rd.z;
    alpha=0.;
    vec3 bgc = bgcol(rd);
    if (t < 0.)
        return bgc;
    vec2 uv = ro.xy + t * rd.xy;
#ifdef NO_SHADOW
    float shad=1.;
#else
    float shad = boxSoftShadow((ro + t * rd), normalize(l_dir+vec3(0.,0.,1.))*rotz(PI*0.65) , BOXDIMS, 1.5);
#endif
    float aofac = smoothstep(-0.95, .75, length(abs(uv) - min(abs(uv), vec2(0.45))));
    aofac = min(aofac,smoothstep(-0.65, 1., shad));
    float lght=max(dot(normalize(ro + t * rd+vec3(0.,-0.,-5.)), normalize(l_dir-vec3(0.,0.,1.))*rotz(PI*0.65)), 0.0);
    vec3 col = mix(vec3(0.4), vec3(.71,.772,0.895), lght*lght* aofac+ 0.05) * aofac;
    alpha=1.-smoothstep(7.,10.,length(uv));
#ifdef SHADOW_ALPHA
    //alpha=clamp(alpha*max(lght*lght*0.95,(1.-aofac)*1.25),0.,1.);
    alpha=clamp(alpha*(1.-aofac)*1.25,0.,1.);
#endif
    return mix(col*length(col)*0.8,bgc,smoothstep(7.,10.,length(uv)));
}

#define swap(a,b) tv=a;a=b;b=tv

vec4 insides(vec3 ro, vec3 rd, vec3 nor_c, vec3 l_dir, out float tout)
{
    tout = -1.;
    vec3 trd=rd;

    vec3 col = vec3(0.);

    float pi = 3.1415926;

    if (abs(nor_c.x) > 0.5)
    {
        rd = rd.xzy * nor_c.x;
        ro = ro.xzy * nor_c.x;
    }
    else if (abs(nor_c.z) > 0.5)
    {
        l_dir *= roty(pi);
        rd = rd.yxz * nor_c.z;
        ro = ro.yxz * nor_c.z;
    }
    else if (abs(nor_c.y) > 0.5)
    {
        l_dir *= rotz(-pi * 0.5);
        rd = rd * nor_c.y;
        ro = ro * nor_c.y;
    }

#ifdef ANIM_SHAPE
    float curvature = (0.001+1.5-1.5*smoothstep(0.,8.5,mod((iTime+tshift)*0.44,20.))*(1.-smoothstep(10.,18.5,mod((iTime+tshift)*0.44,20.))));
    // curvature(to not const above) make compilation on Angle 15+ sec
#else
#ifdef STATIC_SHAPE
    const float curvature = STATIC_SHAPE;
#else
    const float curvature = .5;
#endif
#endif
    float bil_size = 1.;
    vec4 ps = vec4(-bil_size, -bil_size, bil_size, bil_size) * curvature;
    vec4 ph = vec4(-bil_size, bil_size, bil_size, -bil_size) * curvature;
    
    vec4 [3]colx=vec4[3](vec4(0.),vec4(0.),vec4(0.));
    vec3 [3]dx=vec3[3](vec3(-1.),vec3(-1.),vec3(-1.));
    vec4 [3]colxsi=vec4[3](vec4(0.),vec4(0.),vec4(0.));
    int [3]order=int[3](0,1,2);

    for (int i = 0; i < 3 + ANGLE_loops; i++)
    {
        if (abs(nor_c.x) > 0.5)
        {
            ro *= rotz(-pi * (1. / float(3)));
            rd *= rotz(-pi * (1. / float(3)));
        }
        else if (abs(nor_c.z) > 0.5)
        {
            ro *= rotz(pi * (1. / float(3)));
            rd *= rotz(pi * (1. / float(3)));
        }
        else if (abs(nor_c.y) > 0.5)
        {
            ro *= rotx(pi * (1. / float(3)));
            rd *= rotx(pi * (1. / float(3)));
        }
        vec3 normnew;
        float tnew;
        bool si;
        float tsi;
        vec3 normsi;
        float fade;
        float fadesi;

        if (iBilinearPatch(ro, rd, ps, ph, bil_size, tnew, normnew, si, tsi, normsi, fade, fadesi))
        {
            if (tnew > 0.)
            {
                vec4 tcol, tcolsi;
                calcColor(ro, rd, normnew, tnew, bil_size, i, si, tsi, tcol, tcolsi);
                if (tcol.a > 0.0)
                {
                    {
                        vec3 tvalx = vec3(tnew, float(si), tsi);
                        dx[i]=tvalx;
                    }
#ifdef DEBUG
                    colx[i]=tcol;
                    if (si)colxsi[i]=tcolsi;
#else

                    float dif = clamp(dot(normnew, l_dir), 0.0, 1.0);
                    float amb = clamp(0.5 + 0.5 * dot(normnew, l_dir), 0.0, 1.0);

                    {
#ifdef USE_COLOR
                        vec3 shad = 0.57 * color_blue * amb + 1.5*color_blue.bgr * dif;
                        const vec3 tcr = color_red;
#else
                        vec3 shad = vec3(0.32, 0.43, 0.54) * amb + vec3(1.0, 0.9, 0.7) * dif;
                        const vec3 tcr = vec3(1.,0.21,0.11);
#endif
                        float ta = clamp(length(tcol.rgb),0.,1.);
                        tcol=clamp(tcol*tcol*2.,0.,1.);
                        vec4 tvalx =
                            vec4((tcol.rgb*shad*1.4 + 3.*(tcr*tcol.rgb)*clamp(1.-(amb+dif),0.,1.)), min(tcol.a,ta));
                        tvalx.rgb=clamp(2.*tvalx.rgb*tvalx.rgb,0.,1.);
                        tvalx*=(min(fade*5.,1.));
                        colx[i]=tvalx;
                    }
                    if (si)
                    {
                        dif = clamp(dot(normsi, l_dir), 0.0, 1.0);
                        amb = clamp(0.5 + 0.5 * dot(normsi, l_dir), 0.0, 1.0);
                        {
#ifdef USE_COLOR
                            vec3 shad = 0.57 * color_blue * amb + 1.5*color_blue.bgr * dif;
                            const vec3 tcr = color_red;
#else
                            vec3 shad = vec3(0.32, 0.43, 0.54) * amb + vec3(1.0, 0.9, 0.7) * dif;
                            const vec3 tcr = vec3(1.,0.21,0.11);
#endif
                            float ta = clamp(length(tcolsi.rgb),0.,1.);
                            tcolsi=clamp(tcolsi*tcolsi*2.,0.,1.);
                            vec4 tvalx =
                                vec4(tcolsi.rgb * shad + 3.*(tcr*tcolsi.rgb)*clamp(1.-(amb+dif),0.,1.), min(tcolsi.a,ta));
                            tvalx.rgb=clamp(2.*tvalx.rgb*tvalx.rgb,0.,1.);
                            tvalx.rgb*=(min(fadesi*5.,1.));
                            colxsi[i]=tvalx;
                        }
                    }
#endif
                }
            }
        }
    }
    // transparency logic and layers sorting 
    float a = 1.;
    if (dx[0].x < dx[1].x){{vec3 swap(dx[0], dx[1]);}{int swap(order[0], order[1]);}}
    if (dx[1].x < dx[2].x){{vec3 swap(dx[1], dx[2]);}{int swap(order[1], order[2]);}}
    if (dx[0].x < dx[1].x){{vec3 swap(dx[0], dx[1]);}{int swap(order[0], order[1]);}}

    tout = max(max(dx[0].x, dx[1].x), dx[2].x);

    if (dx[0].y < 0.5)
    {
        a=colx[order[0]].a;
    }

#if !(defined(DEBUG)&&defined(BUG))
    
    // self intersection
    bool [3] rul= bool[3](
        ((dx[0].y > 0.5) && (dx[1].x <= 0.)),
        ((dx[1].y > 0.5) && (dx[0].x > dx[1].z)),
        ((dx[2].y > 0.5) && (dx[1].x > dx[2].z))
    );
    for(int k=0;k<3;k++){
        if(rul[k]){
            vec4 tcolxsi = vec4(0.);
            tcolxsi=colxsi[order[k]];
            vec4 tcolx = vec4(0.);
            tcolx=colx[order[k]];

            vec4 tvalx = mix(tcolxsi, tcolx, tcolx.a);
            colx[order[k]]=tvalx;

            vec4 tvalx2 = mix(vec4(0.), tvalx, max(tcolx.a, tcolxsi.a));
            colx[order[k]]=tvalx2;
        }
    }

#endif

    float a1 = (dx[1].y < 0.5) ? colx[order[1]].a : ((dx[1].z > dx[0].x) ? colx[order[1]].a : 1.);
    float a2 = (dx[2].y < 0.5) ? colx[order[2]].a : ((dx[2].z > dx[1].x) ? colx[order[2]].a : 1.);
    col = mix(mix(colx[order[0]].rgb, colx[order[1]].rgb, a1), colx[order[2]].rgb, a2);
    a = max(max(a, a1), a2);
    return vec4(col, a);
}

void mainImage(out vec4 fragColor, in vec2 fragCoord)
{
    float osc = 0.5;
    vec3 l_dir = normalize(vec3(0., 1., 0.));
    l_dir *= rotz(0.5);
    float mouseY = 1.0 * 0.5 * PI;
#ifdef MOUSE_control
    mouseY = (1.0 - 1.15 * iMouse.y / iResolution.y) * 0.5 * PI;
    if(iMouse.y < 1.)
#endif
#ifdef CAMERA_POS
    mouseY = PI*CAMERA_POS;
#else
    mouseY = PI*0.49 - smoothstep(0.,8.5,mod((iTime+tshift)*0.33,25.))*(1.-smoothstep(14.,24.0,mod((iTime+tshift)*0.33,25.))) * 0.55 * PI;
#endif
#ifdef ROTATION_SPEED
    float mouseX = -2.*PI-0.25*(iTime*ROTATION_SPEED+tshift);
#else
    float mouseX = -2.*PI-0.25*(iTime+tshift);
#endif
#ifdef MOUSE_control
    mouseX+=-(iMouse.x / iResolution.x) * 2. * PI;
#endif
    
#ifdef CAMERA_FAR
    vec3 eye = (2. + CAMERA_FAR) * vec3(cos(mouseX) * cos(mouseY), sin(mouseX) * cos(mouseY), sin(mouseY));
#else
    vec3 eye = 4. * vec3(cos(mouseX) * cos(mouseY), sin(mouseX) * cos(mouseY), sin(mouseY));
#endif
    vec3 w = normalize(-eye);
    vec3 up = vec3(0., 0., 1.);
    vec3 u = normalize(cross(w, up));
    vec3 v = cross(u, w);

    vec4 tot=vec4(0.);
#ifdef AA_CUBE
    const int AA = AA_CUBE;
    vec3 incol_once=vec3(0.);
    bool in_once=false;
    vec4 incolbg_once=vec4(0.);
    bool bg_in_once=false;
    vec4 outcolbg_once=vec4(0.);
    bool bg_out_once=false;
    for( int mx=0; mx<AA; mx++ )
    for( int nx=0; nx<AA; nx++ )
    {
    vec2 o = vec2(mod(float(mx+AA/2),float(AA)),mod(float(nx+AA/2),float(AA))) / float(AA) - 0.5;
    vec2 uv = (fragCoord + o - 0.5 * iResolution.xy) / iResolution.x;
#else
    vec2 uv = (fragCoord - 0.5 * iResolution.xy) / iResolution.x;
#endif
    vec3 rd = normalize(w * FDIST + uv.x * u + uv.y * v);

    vec3 ni;
    float t = box(eye, rd, BOXDIMS, ni, true);
    vec3 ro = eye + t * rd;
    vec2 coords = ro.xy * ni.z/BOXDIMS.xy + ro.yz * ni.x/BOXDIMS.yz + ro.zx * ni.y/BOXDIMS.zx;
    float fadeborders = (1.-smoothstep(0.915,1.05,abs(coords.x)))*(1.-smoothstep(0.915,1.05,abs(coords.y)));

    if (t > 0.)
    {
        float ang = -iTime * 0.33;
        vec3 col = vec3(0.);
#ifdef AA_CUBE
        if(in_once)col=incol_once;
        else{
        in_once=true;
#endif
        float R0 = (IOR - 1.) / (IOR + 1.);
        R0 *= R0;

        vec2 theta = vec2(0.);
        vec3 n = vec3(cos(theta.x) * sin(theta.y), sin(theta.x) * sin(theta.y), cos(theta.y));

        vec3 nr = n.zxy * ni.x + n.yzx * ni.y + n.xyz * ni.z;
        vec3 rdr = reflect(rd, nr);
        float talpha;
        vec3 reflcol = background(ro, rdr, l_dir,talpha);

        vec3 rd2 = refract(rd, nr, 1. / IOR);

        float accum = 1.;
        vec3 no2 = ni;
        vec3 ro_refr = ro;

        vec4 [2] colo = vec4[2](vec4(0.),vec4(0.));

        for (int j = 0; j < 2 + ANGLE_loops; j++)
        {
            float tb;
            vec2 coords2 = ro_refr.xy * no2.z + ro_refr.yz * no2.x + ro_refr.zx * no2.y;
            vec3 eye2 = vec3(coords2, -1.);
            vec3 rd2trans = rd2.yzx * no2.x + rd2.zxy * no2.y + rd2.xyz * no2.z;

            rd2trans.z = -rd2trans.z;
            vec4 internalcol = insides(eye2, rd2trans, no2, l_dir, tb);
            if (tb > 0.)
            {
                internalcol.rgb *= accum;
                colo[j]=internalcol;
            }

            if ((tb <= 0.) || (internalcol.a < 1.))
            {
                float tout = box(ro_refr, rd2, BOXDIMS, no2, false);
                no2 = n.zyx * no2.x + n.xzy * no2.y + n.yxz * no2.z;
                vec3 rout = ro_refr + tout * rd2;
                vec3 rdout = refract(rd2, -no2, IOR);
                float fresnel2 = R0 + (1. - R0) * pow(1. - dot(rdout, no2), 1.3);
                rd2 = reflect(rd2, -no2);

#ifdef backside_refl
                if((dot(rdout, no2))>0.5){fresnel2=1.;}
#endif
                ro_refr = rout;
                ro_refr.z = max(ro_refr.z, -0.999);

                accum *= fresnel2;
            }
        }
        float fresnel = R0 + (1. - R0) * pow(1. - dot(-rd, nr), 5.);
        col = mix(mix(colo[1].rgb * colo[1].a, colo[0].rgb, colo[0].a)*fadeborders, reflcol, pow(fresnel, 1.5));
        col=clamp(col,0.,1.);
#ifdef AA_CUBE
        }
        incol_once=col;
        if(!bg_in_once){
        bg_in_once=true;
        float alpha;
        incolbg_once = vec4(background(eye, rd, l_dir, alpha), 0.15);
#if defined(BG_ALPHA)||defined(ONLY_BOX)||defined(SHADOW_ALPHA)
        incolbg_once.w = alpha;
#endif
        }
#endif
        
        float cineshader_alpha = 0.;
        cineshader_alpha = clamp(0.15*dot(eye,ro),0.,1.);
        vec4 tcolx = vec4(col, cineshader_alpha);
#if defined(BG_ALPHA)||defined(ONLY_BOX)||defined(SHADOW_ALPHA)
        tcolx.w = 1.;
#endif
        tot += tcolx;
    }
    else
    {
        vec4 tcolx = vec4(0.);
#ifdef AA_CUBE
        if(!bg_out_once){
        bg_out_once=true;
#endif
        float alpha;
        tcolx = vec4(background(eye, rd, l_dir, alpha), 0.15);
#if defined(BG_ALPHA)||defined(ONLY_BOX)||defined(SHADOW_ALPHA)
        tcolx.w = alpha;
#endif
#ifdef AA_CUBE
        outcolbg_once=tcolx;
        }else tcolx=max(outcolbg_once,incolbg_once);
#endif
        tot += tcolx;
    }
#ifdef AA_CUBE
    }
    tot /= float(AA*AA);
#endif
    fragColor = tot;
#ifdef NO_ALPHA
    fragColor.w = 1.;
#endif
    fragColor.rgb=clamp(fragColor.rgb,0.,1.);
#if defined(BG_ALPHA)||defined(ONLY_BOX)||defined(SHADOW_ALPHA)
    fragColor.rgb=fragColor.rgb*fragColor.w+texture(iChannel0, fragCoord/iResolution.xy).rgb*(1.-fragColor.w);
#endif
    //fragColor=vec4(fragColor.w);
}
"""

src_js = """
////////////////// Jump Sphere Ray Traycing
//drag the window LR to control roughness
//--graphics setting (lower = better fps)---------------------------------------
#define AVERAGECOUNT 16
#define MAX_BOUNCE 32

//--scene data------------------------------------------------------------------
#define SPHERECOUNT 6
//xyz = pos, w = radius
const vec4 AllSpheres[SPHERECOUNT]=vec4[SPHERECOUNT](
    vec4(0.0,0.0,0.0,2.0),//sphere A
    vec4(0.0,0.0,-1.0,2.0),//sphere B
    vec4(0.0,-1002.0,0.0,1000.0),//ground
    vec4(0.0,0.0,+1002,1000.0),//back wall
    vec4(-1004.0,0.0,0.0,1000.0),//left wall    
    vec4(+1004.0,0.0,0.0,1000.0)//right wall
);
//-----------------------------------------------------------------------
float raySphereIntersect(vec3 r0, vec3 rd, vec3 s0, float sr) {
    // - r0: ray origin
    // - rd: normalized ray direction
    // - s0: sphere center
    // - sr: sphere radius
    // - Returns distance from r0 to first intersecion with sphere,
    //   or -1.0 if no intersection.
    float a = dot(rd, rd);
    vec3 s0_r0 = r0 - s0;
    float b = 2.0 * dot(rd, s0_r0);
    float c = dot(s0_r0, s0_r0) - (sr * sr);
    if (b*b - 4.0*a*c < 0.0) {
        return -1.0;
    }
    return (-b - sqrt((b*b) - 4.0*a*c))/(2.0*a);
}
//-----------------------------------------------------------------------
struct HitData
{
    float rayLength;
    vec3 normal;
};
HitData AllObjectsRayTest(vec3 rayPos, vec3 rayDir)
{
    HitData hitData;
    hitData.rayLength = 9999.0; //default value if can't hit anything

    for(int i = 0; i < SPHERECOUNT; i++)
    {
        vec3 sphereCenter = AllSpheres[i].xyz;
        float sphereRadius = AllSpheres[i].w;
        //----hardcode sphere pos animations-------------------------------------
        if(i == 0)
        {
            float t = fract(iTime * 0.7);
            t = -4.0 * t * t + 4.0 * t;
            sphereCenter.y += t * 0.7;
            
            sphereCenter.x += sin(iTime) * 2.0;
            sphereCenter.z += cos(iTime) * 2.0;
        }

        if(i == 1)
        {
            float t = fract(iTime*0.47);
            t = -4.0 * t * t + 4.0 * t;
            sphereCenter.y += t * 1.7;

            sphereCenter.x += sin(iTime+3.14) * 2.0;
            sphereCenter.z += cos(iTime+3.14) * 2.0;
        }
        //---------------------------------------

        float resultRayLength = raySphereIntersect(rayPos,rayDir,sphereCenter,sphereRadius);
        if(resultRayLength < hitData.rayLength && resultRayLength > 0.001)
        {
            //if a shorter(better) hit ray found, update
            hitData.rayLength = resultRayLength;
            vec3 hitPos = rayPos + rayDir * resultRayLength;
            hitData.normal = normalize(hitPos - sphereCenter);
        }
    }

    //all test finished, return shortest(best) hit data
    return hitData;
}
//--random functions-------------------------------------------------------------------
float rand01(float seed) { return fract(sin(seed)*43758.5453123); }
vec3 randomInsideUnitSphere(vec3 rayDir,vec3 rayPos, float extraSeed)
{
    return vec3(rand01(iTime * (rayDir.x + rayPos.x + 0.357) * extraSeed),
                rand01(iTime * (rayDir.y + rayPos.y + 16.35647) *extraSeed),
                rand01(iTime * (rayDir.z + rayPos.z + 425.357) * extraSeed));
}
//---------------------------------------------------------------------
vec4 calculateFinalColor(vec3 cameraPos, vec3 cameraRayDir, float AAIndex)
{
    //init
    vec3 finalColor = vec3(0.0);
    float absorbMul = 1.0;
    vec3 rayStartPos = cameraPos;
    vec3 rayDir = cameraRayDir;

    //only for CineShader, to show depth
    float firstHitRayLength = -1.0;

    //can't write recursive function in GLSL, so write it in a for loop
    //will loop until hitting any light source / bounces too many times
    for(int i = 0; i < MAX_BOUNCE; i++)
    {
        HitData h = AllObjectsRayTest(rayStartPos + rayDir * 0.0001,rayDir);//+0.0001 to prevent ray already hit at start pos

        //only for CineShader, to show depth
        firstHitRayLength = firstHitRayLength < 0.0 ? h.rayLength : firstHitRayLength;

        //if ray can't hit anything, rayLength will remain default value 9999.0
        //which enters this if()
        //** 99999 is too large for mobile, use 9900 as threshold now **
        if(h.rayLength >= 9900.0)
        {
            vec3 skyColor = vec3(0.7,0.85,1.0);//hit nothing = hit sky color
            finalColor = skyColor * absorbMul;
            break;
        }

        absorbMul *= 0.8; //every bounce absorb some light(more bounces = darker)

        //update rayStartPos for next bounce
        rayStartPos = rayStartPos + rayDir * h.rayLength; 
        //update rayDir for next bounce
        float rougness = 0.05 + iMouse.x / iResolution.x; //hardcode "drag the window LR to control roughness"
        rayDir = normalize(reflect(rayDir,h.normal) + randomInsideUnitSphere(rayDir,rayStartPos,AAIndex) * rougness);       
    }

    return vec4(finalColor,firstHitRayLength);//alpha nly for CineShader, to show depth
}
//-----------------------------------------------------------------------
void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    // Normalized pixel coordinates (from 0 to 1)
    vec2 uv = fragCoord/iResolution.xy;

    uv = uv * 2.0 - 1.0;//transform from [0,1] to [-1,1]
    uv.x *= iResolution.x / iResolution.y; //aspect fix

    vec3 cameraPos = vec3(sin(iTime * 0.47) * 4.0,sin(iTime * 0.7)*8.0+6.0,-25.0);//camera pos animation
    vec3 cameraFocusPoint = vec3(0,0.0 + sin(iTime),0);//camera look target point animation
    vec3 cameraDir = normalize(cameraFocusPoint - cameraPos);
    
    //TEMPCODE: fov & all ray init dir, it is wrong!!!!
    //----------------------------------------------------
    float fovTempMul = 0.2 + sin(iTime * 0.4) * 0.05;//fov animation
    vec3 rayDir = normalize(cameraDir + vec3(uv,0) * fovTempMul);
    //----------------------------------------------------

    vec4 finalColor = vec4(0);
    for(int i = 1; i <= AVERAGECOUNT; i++)
    {
        finalColor+= calculateFinalColor(cameraPos,rayDir, float(i));
    }
    finalColor = finalColor/float(AVERAGECOUNT);//brute force AA & denoise
    finalColor.rgb = pow(finalColor.rgb,vec3(1.0/2.2));//gamma correction
    
    //only for CineShader, to show depth
    float z = finalColor.w; //z is linear world space distance from camera to surface
    float cineShaderZ; //expect 0~1
    cineShaderZ = pow(clamp(1.0 - max(0.0,z-21.0) * (1.0/6.0),0.0,1.0),2.0);

    //result
    fragColor = vec4(finalColor.rgb,cineShaderZ);
}
"""

src_ct = """
////////////////// Clouds tunnel

mat2 rot(in float a){float c = cos(a), s = sin(a);return mat2(c,s,-s,c);}
const mat3 m3 = mat3(0.33338, 0.56034, -0.71817, -0.87887, 0.32651, -0.15323, 0.15162, 0.69596, 0.61339)*1.93;
float mag2(vec2 p){return dot(p,p);}
float linstep(in float mn, in float mx, in float x){ return clamp((x - mn)/(mx - mn), 0., 1.); }
float prm1 = 0.;
vec2 bsMo = vec2(0);

vec2 disp(float t){ return vec2(sin(t*0.22)*1., cos(t*0.175)*1.)*2.; }

vec2 map(vec3 p)
{
    vec3 p2 = p;
    p2.xy -= disp(p.z).xy;
    p.xy *= rot(sin(p.z+iTime)*(0.1 + prm1*0.05) + iTime*0.09);
    float cl = mag2(p2.xy);
    float d = 0.;
    p *= .61;
    float z = 1.;
    float trk = 1.;
    float dspAmp = 0.1 + prm1*0.2;
    for(int i = 0; i < 5; i++)
    {
        p += sin(p.zxy*0.75*trk + iTime*trk*.8)*dspAmp;
        d -= abs(dot(cos(p), sin(p.yzx))*z);
        z *= 0.57;
        trk *= 1.4;
        p = p*m3;
    }
    d = abs(d + prm1*3.)+ prm1*.3 - 2.5 + bsMo.y;
    return vec2(d + cl*.2 + 0.25, cl);
}

vec4 render( in vec3 ro, in vec3 rd, float time )
{
    vec4 rez = vec4(0);
    const float ldst = 8.;
    vec3 lpos = vec3(disp(time + ldst)*0.5, time + ldst);
    float t = 1.5;
    float fogT = 0.;
    for(int i=0; i<130; i++)
    {
        if(rez.a > 0.99)break;

        vec3 pos = ro + t*rd;
        vec2 mpv = map(pos);
        float den = clamp(mpv.x-0.3,0.,1.)*1.12;
        float dn = clamp((mpv.x + 2.),0.,3.);
        
        vec4 col = vec4(0);
        if (mpv.x > 0.6)
        {

            col = vec4(sin(vec3(5.,0.4,0.2) + mpv.y*0.1 +sin(pos.z*0.4)*0.5 + 1.8)*0.5 + 0.5,0.08);
            col *= den*den*den;
            col.rgb *= linstep(4.,-2.5, mpv.x)*2.3;
            float dif =  clamp((den - map(pos+.8).x)/9., 0.001, 1. );
            dif += clamp((den - map(pos+.35).x)/2.5, 0.001, 1. );
            col.xyz *= den*(vec3(0.005,.045,.075) + 1.5*vec3(0.033,0.07,0.03)*dif);
        }

        float fogC = exp(t*0.2 - 2.2);
        col.rgba += vec4(0.06,0.11,0.11, 0.1)*clamp(fogC-fogT, 0., 1.);
        fogT = fogC;
        rez = rez + col*(1. - rez.a);
        t += clamp(0.5 - dn*dn*.05, 0.09, 0.3);
    }
    return clamp(rez, 0.0, 1.0);
}

float getsat(vec3 c)
{
    float mi = min(min(c.x, c.y), c.z);
    float ma = max(max(c.x, c.y), c.z);
    return (ma - mi)/(ma+ 1e-7);
}

//from my "Will it blend" shader (https://www.shadertoy.com/view/lsdGzN)
vec3 iLerp(in vec3 a, in vec3 b, in float x)
{
    vec3 ic = mix(a, b, x) + vec3(1e-6,0.,0.);
    float sd = abs(getsat(ic) - mix(getsat(a), getsat(b), x));
    vec3 dir = normalize(vec3(2.*ic.x - ic.y - ic.z, 2.*ic.y - ic.x - ic.z, 2.*ic.z - ic.y - ic.x));
    float lgt = dot(vec3(1.0), ic);
    float ff = dot(dir, normalize(ic));
    ic += 1.5*dir*sd*ff*lgt;
    return clamp(ic,0.,1.);
}

void mainImage( out vec4 fragColor, in vec2 fragCoord )
{
    vec2 q = fragCoord.xy/iResolution.xy;
    vec2 p = (gl_FragCoord.xy - 0.5*iResolution.xy)/iResolution.y;
    bsMo = (iMouse.xy - 0.5*iResolution.xy)/iResolution.y;

    float time = iTime*3.;
    vec3 ro = vec3(0,0,time);

    ro += vec3(sin(iTime)*0.5,sin(iTime*1.)*0.,0);

    float dspAmp = .85;
    ro.xy += disp(ro.z)*dspAmp;
    float tgtDst = 3.5;

    vec3 target = normalize(ro - vec3(disp(time + tgtDst)*dspAmp, time + tgtDst));
    ro.x -= bsMo.x*2.;
    vec3 rightdir = normalize(cross(target, vec3(0,1,0)));
    vec3 updir = normalize(cross(rightdir, target));
    rightdir = normalize(cross(updir, target));
    vec3 rd=normalize((p.x*rightdir + p.y*updir)*1. - target);
    rd.xy *= rot(-disp(time + 3.5).x*0.2 + bsMo.x);
    prm1 = smoothstep(-0.4, 0.4,sin(iTime*0.3));
    vec4 scn = render(ro, rd, time);

    vec3 col = scn.rgb;
    col = iLerp(col.bgr, col.rgb, clamp(1.-prm1,0.05,1.));

    col = pow(col, vec3(.55,0.65,0.6))*vec3(1.,.97,.9);

    col *= pow( 16.0*q.x*q.y*(1.0-q.x)*(1.0-q.y), 0.12)*0.7+0.3; //Vign

    fragColor = vec4( col, 1.0 );
}
"""

src_lc = """
////////////////// LIQUID CARBON
// ***********************************************************
// Alcatraz / Rhodium 4k Intro liquid carbon
// by Jochen "Virgill" Feldkötter
//
// 4kb executable: http://www.pouet.net/prod.php?which=68239
// Youtube: https://www.youtube.com/watch?v=YK7fbtQw3ZU
// ***********************************************************

#define time iTime
#define res iResolution

float bounce;

// signed box
float sdBox(vec3 p,vec3 b)
{
  vec3 d=abs(p)-b;
  return min(max(d.x,max(d.y,d.z)),0.)+length(max(d,0.));
}

// rotation
void pR(inout vec2 p,float a) 
{
    p=cos(a)*p+sin(a)*vec2(p.y,-p.x);
}

// 3D noise function (IQ)
float noise(vec3 p)
{
    vec3 ip=floor(p);
    p-=ip; 
    vec3 s=vec3(7,157,113);
    vec4 h=vec4(0.,s.yz,s.y+s.z)+dot(ip,s);
    p=p*p*(3.-2.*p); 
    h=mix(fract(sin(h)*43758.5),fract(sin(h+s.x)*43758.5),p.x);
    h.xy=mix(h.xz,h.yw,p.y);
    return mix(h.x,h.y,p.z); 
}

float map(vec3 p)
{
    p.z-=1.0;
    p*=0.9;
    pR(p.yz,bounce*1.+0.4*p.x);
    return sdBox(p+vec3(0,sin(1.6*time),0),vec3(20.0, 0.05, 1.2))-.4*noise(8.*p+3.*bounce);
}

//  normal calculation
vec3 calcNormal(vec3 pos)
{
    float eps=0.0001;
    float d=map(pos);
    return normalize(vec3(map(pos+vec3(eps,0,0))-d,map(pos+vec3(0,eps,0))-d,map(pos+vec3(0,0,eps))-d));
}

//  standard sphere tracing inside and outside
float castRayx(vec3 ro,vec3 rd) 
{
    float function_sign=(map(ro)<0.)?-1.:1.;
    float precis=.0001;
    float h=precis*2.;
    float t=0.;
    for(int i=0;i<120;i++) 
    {
        if(abs(h)<precis||t>12.)break;
        h=function_sign*map(ro+rd*t);
        t+=h;
    }
    return t;
}

//  refraction
float refr(vec3 pos,vec3 lig,vec3 dir,vec3 nor,float angle,out float t2, out vec3 nor2)
{
    float h=0.;
    t2=2.;
    vec3 dir2=refract(dir,nor,angle);  
    for(int i=0;i<50;i++) 
    {
        if(abs(h)>3.) break;
        h=map(pos+dir2*t2);
        t2-=h;
    }
    nor2=calcNormal(pos+dir2*t2);
    return(.5*clamp(dot(-lig,nor2),0.,1.)+pow(max(dot(reflect(dir2,nor2),lig),0.),8.));
}

//  softshadow 
float softshadow(vec3 ro,vec3 rd) 
{
    float sh=1.;
    float t=.02;
    float h=.0;
    for(int i=0;i<22;i++)  
    {
        if(t>20.)continue;
        h=map(ro+rd*t);
        sh=min(sh,4.*h/t);
        t+=h;
    }
    return sh;
}

//  main function
void mainImage(out vec4 fragColor,in vec2 fragCoord)
{
    bounce=abs(fract(0.05*time)-.5)*20.; // triangle function
    vec2 uv=gl_FragCoord.xy/res.xy; 
    vec2 p=uv*2.-1.;

//  bouncy cam every 10 seconds
    float wobble=(fract(.1*(time-1.))>=0.9)?fract(-time)*0.1*sin(30.*time):0.;

//  camera
    vec3 dir = normalize(vec3(2.*gl_FragCoord.xy -res.xy, res.y));
    vec3 org = vec3(0,2.*wobble,-3.);  

//  standard sphere tracing:
    vec3 color = vec3(0.);
    vec3 color2 =vec3(0.);
    float t=castRayx(org,dir);
    vec3 pos=org+dir*t;
    vec3 nor=calcNormal(pos);

//  lighting:
    vec3 lig=normalize(vec3(.2,6.,.5));
//  scene depth    
    float depth=clamp((1.-0.09*t),0.,1.);

    vec3 pos2 = vec3(0.);
    vec3 nor2 = vec3(0.);
    if(t<12.0)
    {
        color2 = vec3(max(dot(lig,nor),0.)  +  pow(max(dot(reflect(dir,nor),lig),0.),16.));
        color2 *=clamp(softshadow(pos,lig),0.,1.);  // shadow               
        float t2;
        color2.rgb +=refr(pos,lig,dir,nor,0.9, t2, nor2)*depth;
        color2-=clamp(.1*t2,0.,1.);             // inner intensity loss
    }

    float tmp = 0.;
    float T = 1.;

//  animation of glow intensity    
    float intensity = 0.1*-sin(.209*time+1.)+0.05; 
    for(int i=0; i<128; i++)
    {
        float density = 0.; float nebula = noise(org+bounce);
        density=intensity-map(org+.5*nor2)*nebula;
        if(density>0.)
        {
            tmp = density / 128.;
            T *= 1. -tmp * 100.;
            if( T <= 0.) break;
        }
        org += dir*0.078;
    }
    vec3 basecol=vec3(1./1. ,  1./4. , 1./16.);
    T=clamp(T,0.,1.5); 
    color += basecol* exp(4.*(0.5-T) - 0.8);
    color2*=depth;
    color2+= (1.-depth)*noise(6.*dir+0.3*time)*.1;  // subtle mist

//  scene depth included in alpha channel
    fragColor = vec4(vec3(1.*color+0.8*color2)*1.3,abs(0.67-depth)*2.+4.*wobble);
}

out vec4 vFragColor;

void main() {
    vec4 c;
    mainImage(c, fragCoord);
    vFragColor = c;
}
"""

