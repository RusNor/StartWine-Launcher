from enum import Enum

class Shaders(Enum):

    src_atari = """
    // CC0: Atari Windows Terminal Shader
    //  The Atari rainbow logo as I remember it
    #define TIME        iTime
    #define RESOLUTION  iResolution

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    const vec4 hsv2rgb_K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 hsv2rgb(vec3 c) {
      vec3 p = abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www);
      return c.z * mix(hsv2rgb_K.xxx, clamp(p - hsv2rgb_K.xxx, 0.0, 1.0), c.y);
    }

    // License: WTFPL, author: sam hocevar, found: https://stackoverflow.com/a/17897228/418488
    //  Macro version of above to enable compile-time constants
    #define HSV2RGB(c)  (c.z * mix(hsv2rgb_K.xxx, clamp(abs(fract(c.xxx + hsv2rgb_K.xyz) * 6.0 - hsv2rgb_K.www) - hsv2rgb_K.xxx, 0.0, 1.0), c.y))

    const float 
        outer = .0125*0.5,
        inner = .0125*0.5,
        full  = inner+outer,
        pi    = acos(-1.),
        tau   = 2.*pi;

    const vec3 
        lightCol0 = HSV2RGB(vec3(0.58, 0.8, 2.)),
        lightCol1 = HSV2RGB(vec3(0.68, 0.5, 2.)),
        sunCol    = HSV2RGB(vec3(0.08, 0.8, 5E-2)),
        lightPos0 = vec3(1.1, 1.-0.5, 1.5),
        lightPos1 = vec3(-1.5, 0, 1.5);

    // License: Unknown, author: Matt Taylor (https://github.com/64), found: https://64.github.io/tonemapping/
    vec3 aces_approx(vec3 v) {
      v = max(v, 0.0);
      v *= 0.6;
      float a = 2.51;
      float b = 0.03;
      float c = 2.43;
      float d = 0.59;
      float e = 0.14;
      return clamp((v*(a*v+b))/(v*(c*v+d)+e), 0.0, 1.0);
    }

    // License: Unknown, author: Unknown, found: don't remember
    float hash(vec2 co) {
      return fract(sin(dot(co.xy ,vec2(12.9898,58.233))) * 13758.5453);
    }

    // IQ's polynomial min
    float pmin(float a, float b, float k) {
      float h = clamp(0.5+0.5*(b-a)/k, 0.0, 1.0);
      return mix(b, a, h) - k*h*(1.0-h);
    }

    float pmax(float a, float b, float k) {
      return -pmin(-a, -b, k);
    }

    // IQ's box
    float box(vec2 p, vec2 b) {
      vec2 d = abs(p)-b;
      return length(max(d,0.0)) + min(max(d.x,d.y),0.0);
    }

    // IQ's segment
    float parabola(vec2 pos, float k) {
      pos.x = abs(pos.x);
      float ik = 1.0/k;
      float p = ik*(pos.y - 0.5*ik)/3.0;
      float q = 0.25*ik*ik*pos.x;
      float h = q*q - p*p*p;
      float r = sqrt(abs(h));
      float x = (h>0.0) ? pow(q+r,1.0/3.0) - pow(abs(q-r),1.0/3.0)*sign(r-q) :
        2.0*cos(atan(r,q)/3.0)*sqrt(p);

      return length(pos-vec2(x,k*x*x)) * sign(pos.x-x);
    }

    float atari(vec2 p) {
      p.x = abs(p.x);
      float db = box(p, vec2(0.36, 0.32));

      float dp0 = -parabola(p-vec2(0.4, -0.235), 4.0);
      float dy0 = p.x-0.115;
      float d0 = mix(dp0, dy0, smoothstep(-0.25, 0.125, p.y)); // Very hacky

      float dp1 = -parabola(p-vec2(0.4, -0.32), 3.0);
      float dy1 = p.x-0.07;
      float d1 = mix(dp1, dy1, smoothstep(-0.39, 0.085, p.y)); // Very hacky

      float d2 = p.x-0.035;
      const float sm = 0.025;
      float d = 1E6;
      d = min(d, max(d0, -d1));;
      d = pmin(d, d2, sm);
      d = pmax(d, db, sm);

      return d;
    }

    float df(vec2 p) {
      const float z = 2.;
      return atari(p/z)*z;
    }

    float hf(vec2 p) {  
      float d0 = df(p);
      float x = clamp(full+(d0-outer), 0., full);
      float h = sqrt((full*full-x*x))/full;

      return -0.5*full*h;
    }

    vec3 nf(vec2 p) {
      vec2 e = vec2(sqrt(8.)/RESOLUTION.y, 0);

      vec3 n;
      n.x = hf(p + e.xy) - hf(p - e.xy);
      n.y = hf(p + e.yx) - hf(p - e.yx);
      n.z = 2.0*e.x;

      return normalize(n);
    }

    float mountain(float p) {
      p*= 5.;
      p += -1.+5E-3*TIME;
      float h = 0.;
      float a = 1.;
      for (int i = 0; i < 3; ++i) {
        h += a*sin(p);
        a *= .5;
        p = 1.99*p+1.;
      }
      return 0.05*h+0.05;
    }

    vec3 layer0(vec3 col, vec2 p, float aa, float tm) {
      vec3 ro    = vec3(0,0,tm),
          rd = normalize(vec3(p,2)),
          ard   = abs(rd),
          srd   = sign(rd);

      for (float i = 1.; i < 10.; ++i) {
        float tw = -(ro.x-6.*sqrt(i))/ard.x;

        if (tw>1E3) continue;

        vec3 wp = ro+rd*tw;
        vec2 wp2 = (ro+rd*tw).yz*2E-2, wn2 = round(wp2), wc2 = wp2 - wn2;

        if (hash(wn2+i+.5*srd.x) < .5) wc2 = vec2(wc2.y, -wc2.x);

        float fo  = smoothstep(-sqrt(.5), 1., sin(.1*wp.z+tm+i+srd.x)),
            wd  = abs(min(length(wc2+.5)-.5, length(wc2-.5)-.5))-25E-3;

        col += (1.+sin(vec3(-4,3,1)/2.+5E-2*tw+tm))
          *exp(-3E-3*tw*tw)
          *fo
          *25E-4/max(abs(wd), 3E-3*fo);
      }
      return col;
    }

    vec3 layer1(vec3 col, vec2 p, float aa) {
      float d = df(p);
      vec3  n = nf(p);

      vec3 lcol = vec3(0.);
      vec3 p3 = vec3(p, 0.);

      vec3 ro = vec3(0.,0.,10.);
      vec3 rd = normalize(p3-ro);
      vec3 r = reflect(rd, n);
      vec3 ld0 = normalize(lightPos0-p3);
      vec3 ld1 = normalize(lightPos1-p3);

      float spe0 = pow(max(dot(r, ld0), 0.0), 70.);
      float spe1 = pow(max(dot(r, ld1), 0.0), 40.);

      float m = mountain(p.x);
      float cy = p.y+m;
      vec2 sp = p-vec2(0.0,0.5);
      vec3 topCol = hsv2rgb(vec3(0.58+cy*0.15, 0.95, 1.));
      topCol *= smoothstep(0.7, 0.25, cy);
      topCol += sunCol/max(dot(sp, sp), 1E-2);
      vec3 botCol = hsv2rgb(vec3(0.98-cy*0.2, 0.85, 1.));
      botCol *= tanh(-10.*min(0., cy+0.01)+0.05);

      lcol = mix(topCol, botCol, smoothstep(aa, -aa, cy));

      lcol *= 0.67+0.33*sin(p.y*RESOLUTION.y*tau/max(round(RESOLUTION.y/144.), 6.));
      lcol *= 2.;
      lcol += spe0*lightCol0;
      lcol += spe1*lightCol1;
      lcol -= 0.0125*length(p);

      col *= 1.-0.9*exp(-10.*max(d+0.0125*sqrt(2.), 0.));
      col = mix(col, lcol, smoothstep(aa, -aa, d-outer));
      col = mix(col, vec3(0.), smoothstep(aa, -aa, abs(d-outer)-2E-3));

      return col;
    }

    vec3 effect(vec2 p, vec2 pp) {
      float aa = sqrt(2.)/RESOLUTION.y;
      vec3 col = vec3(0.);

      col = layer0(col, p, aa, 0.5*TIME);
      //col = layer1(col, p, aa);

      col *= smoothstep(sqrt(2.), sqrt(.5), length(pp));
      col = sqrt(aces_approx((col)));
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

    src_psw_blue = """
    /////////////////// Plasma waves

    /* This work is protected under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License
     * more information canbe found at:
     * https://creativecommons.org/licenses/by-nc-sa/3.0/deed.en_US
     */

    const float overallSpeed = 0.1;
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

    const float overallSpeed = 0.1;
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
    const float overallSpeed = 0.1;
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
    const float overallSpeed = 0.1;
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
    const float overallSpeed = 0.1;
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
    const float overallSpeed = 0.1;
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
    const float overallSpeed = 0.1;
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
    const float overallSpeed = 0.1;
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


    src_macos_monteray = """
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

    src_macos_montegray = """
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

        if (col.x >= 0.6 ) {
          fragColor = vec3(0.28,0.36,0.36);
        } else if (col.x >= 0.4) {
          fragColor = vec3(0.49,0.55,0.56);
        } else if (col.x >= 0.2) {
          fragColor = vec3(0.33, 0.47, 0.49);
        } else {
          fragColor = vec3(0.24, 0.39, 0.4);
        }
        return fragColor;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        fragCoord = rotate(fragCoord + vec2(0.0, -300.0), 0.5);
        // Normalized pixel coordinates (from 0 to 1)
        vec3 col0 = scene((fragCoord * 2.0)/iResolution.xy);
        vec3 col1 = scene(((fragCoord * 2.0) + vec2(1.0, 0.0))/iResolution.xy);
        vec3 col2 = scene(((fragCoord * 2.0) + vec2(1.0, 1.0))/iResolution.xy);
        vec3 col3 = scene(((fragCoord * 2.0) + vec2(0.0, 1.0))/iResolution.xy);

        // Output to screen
        fragColor = vec4((col0 + col1 + col2 + col2) / 4.0,1.0);
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

    src_ps3_blue = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.025, 0.035, 0.05);
    const vec3 bottom = vec3(0.25, 0.35, 0.5);
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

    src_ps3_red = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.1, 0.05, 0.05);
    const vec3 bottom = vec3(1.0, 0.2, 0.1);
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

    src_ps3_teal = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.024, 0.032, 0.036);
    const vec3 bottom = vec3(0.24, 0.32, 0.36);
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

    src_ps3_mint = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.04, 0.05, 0.01);
    const vec3 bottom = vec3(0.4, 0.5, 0.1);
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

    src_ps3_golden = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.25, 0.15, 0.025);
    const vec3 bottom = vec3(1.0, 0.6, 0.1);
    //const vec3 top = vec3(0.318, 0.831, 1.0);
    //const vec3 bottom = vec3(0.094, 0.141, 0.424);
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

    src_ps3_purple = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.028, 0.02, 0.036);
    const vec3 bottom = vec3(0.28, 0.20, 0.36);
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

    src_ps3_brown = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.035, 0.027, 0.028);
    const vec3 bottom = vec3(0.35, 0.27, 0.28);
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

    src_ps3_gray = """
    /////////////////// PS3 Home Background

    const vec3 top = vec3(0.028, 0.028, 0.036);
    const vec3 bottom = vec3(0.28, 0.28, 0.36);
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
    /////////////////// Factory windows
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

    src_windows_xp = """
    // The MIT License
    // Copyright © 2025 Gehtsiegarnixan
    // Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    /*
    Note: I made another one because Reddit was being fussy about the Lenna image.

    This is the Bliss (Windows XP wallpaper) shown using Gaussian Mixture, a type 
    of fuzzy clustering. The modeling took 3 minutes for 512 clusters and a data 
    shape of (196 x 110, 5). I think this is a pretty easy and fast method to get 
    images into Shadertoy that aren't available. 

    My Python code to make these from any image can be found at: 
    pastebin.com/Mj4GLMDR

    I used Scikit-learn for the clustering and guide for the GLSL transition: 
    scikit-learn.org/stable/modules/generated/sklearn.mixture.GaussianMixture.html

    The original reference photo of Bliss can be found here: 
    archive.org/details/windows-xp-bliss-wallpaper
    */

    // Enable repeating Tiling (1=true|0=false)
    #define TILING 0

    // Abbreviations
    #define v(x,y,z) vec3(x,y,z)
    #define u(x,y) vec2(x,y)
    #define m(a,b,c,d) mat2(a,b,c,d)

    // Cluster Data made with this python code https://pastebin.com/Mj4GLMDR
    #define COUNT 512
    #define SCALES vec4(1e-4,1e-3,1e-3,1e-5)
    const int WEIGHTS[COUNT] = int[](20,18,17,33,41,12,37,21,29,1,18,7,23,26,14,23,23,20,16,13,9,19,15,26,42,48,16,9,4,17,22,11,14,11,13,25,26,10,12,10,32,47,23,44,19,58,16,22,27,13,24,16,9,36,15,21,14,6,18,43,24,3,11,11,23,18,16,19,23,31,7,9,5,38,30,16,15,5,60,16,7,31,11,3,22,10,16,7,45,3,9,28,5,17,10,23,14,20,27,29,13,27,12,7,8,11,22,33,2,13,11,24,45,36,7,25,12,19,25,22,28,19,25,9,21,19,14,22,16,26,10,12,15,6,9,28,55,7,20,44,44,14,12,8,37,27,19,31,38,7,11,4,4,13,11,22,32,8,13,15,27,47,8,24,29,8,48,34,3,13,23,20,16,14,37,21,1,263,3,16,15,31,55,19,27,30,23,16,28,33,18,20,7,30,28,16,16,24,13,25,14,15,7,20,11,26,39,21,17,16,18,15,18,13,22,21,5,26,25,24,17,7,11,14,23,42,17,9,9,23,11,7,19,13,26,4,8,30,22,17,5,13,29,18,22,62,39,26,22,26,23,26,21,22,17,41,29,12,17,16,11,17,5,22,3,17,17,18,7,1,21,2,20,7,16,20,28,11,55,0,21,17,13,16,7,60,56,23,21,13,16,22,5,29,16,17,27,23,21,2,27,17,21,22,15,24,15,3,8,18,14,7,14,24,9,10,7,13,20,13,20,15,27,13,24,9,14,19,9,20,7,12,18,11,8,5,7,12,15,14,12,8,11,30,13,7,13,20,30,47,10,13,17,13,14,22,34,2,25,4,16,13,7,31,16,12,19,9,25,11,18,10,11,2,25,22,14,11,15,8,9,10,24,17,13,13,24,37,5,8,24,9,23,27,17,6,14,17,19,14,21,7,11,11,28,14,26,11,34,40,13,28,29,12,5,19,44,23,12,6,2,29,22,9,4,35,23,9,21,13,1,5,20,13,5,30,14,11,19,9,25,6,22,7,5,29,11,23,13,25,20,11,10,7,24,38,14,133,14,16,21,5,39,12,11,2,24,18,14,9,15,10,13,7,45,20,22,31,4,26,7,25,30,4,41,19,2,16,35,12,19,14,20,6,33,24,32,0,17,13,12,15,31,20,3,14,7,13,10,10,18,5);
    const vec3 COLORS[COUNT] = vec3[](v(661,546,326),v(293,433,614),v(243,438,599),v(611,547,297),v(547,388,700),v(758,501,381),v(901,495,467),v(759,520,394),v(544,575,257),v(464,432,668),v(215,467,554),v(508,595,238),v(859,498,443),v(400,420,650),v(834,501,429),v(605,383,724),v(310,432,593),v(642,541,313),v(271,438,578),v(950,498,493),v(575,571,287),v(289,431,619),v(952,497,495),v(514,392,691),v(527,586,247),v(645,533,312),v(434,628,218),v(951,503,498),v(297,430,615),v(668,533,337),v(280,427,617),v(701,539,358),v(707,533,354),v(626,548,307),v(939,497,487),v(362,419,639),v(801,516,409),v(591,558,286),v(424,559,345),v(520,588,248),v(618,556,303),v(311,425,619),v(332,427,607),v(314,424,622),v(553,576,268),v(825,514,431),v(598,383,717),v(642,547,316),v(693,530,350),v(614,559,304),v(545,388,699),v(501,600,246),v(559,574,267),v(310,426,630),v(577,560,276),v(734,522,376),v(386,412,650),v(844,501,429),v(767,519,388),v(270,434,608),v(446,407,655),v(719,525,360),v(273,441,595),v(93,503,498),v(553,572,263),v(286,429,619),v(959,502,499),v(790,498,402),v(887,506,463),v(513,594,245),v(261,434,579),v(864,504,441),v(478,390,696),v(297,432,616),v(463,618,217),v(469,415,673),v(763,508,388),v(676,370,751),v(310,426,616),v(93,528,478),v(285,428,626),v(799,517,411),v(952,501,496),v(756,518,386),v(714,515,356),v(878,505,454),v(565,567,274),v(898,497,461),v(299,428,619),v(255,572,344),v(621,551,310),v(700,525,357),v(757,522,389),v(204,442,587),v(551,387,707),v(289,434,615),v(604,557,293),v(606,390,711),v(762,521,386),v(285,430,622),v(533,586,270),v(415,408,646),v(888,499,458),v(865,499,446),v(255,443,571),v(754,516,383),v(944,498,490),v(646,538,323),v(672,524,333),v(615,375,736),v(291,429,620),v(541,385,710),v(960,501,501),v(298,429,621),v(444,414,614),v(927,497,482),v(889,496,459),v(341,426,608),v(323,422,636),v(434,630,213),v(240,432,600),v(767,497,387),v(311,430,613),v(609,381,716),v(646,541,323),v(620,542,300),v(584,565,284),v(964,504,500),v(463,397,683),v(687,535,344),v(960,504,498),v(551,571,262),v(747,522,375),v(568,388,707),v(668,548,336),v(610,543,292),v(307,432,605),v(448,409,661),v(682,540,340),v(623,544,302),v(270,436,582),v(415,411,645),v(693,541,350),v(202,439,592),v(314,428,621),v(455,617,229),v(598,562,293),v(525,587,244),v(246,437,602),v(876,504,451),v(662,535,333),v(246,433,607),v(692,530,352),v(575,562,273),v(278,429,622),v(491,603,229),v(276,434,601),v(280,429,615),v(525,393,693),v(251,437,617),v(693,538,346),v(662,372,744),v(605,559,294),v(655,539,322),v(206,472,549),v(449,413,662),v(744,520,379),v(896,506,469),v(233,439,608),v(641,543,315),v(596,557,288),v(530,582,247),v(290,433,606),v(297,422,632),v(782,517,407),v(652,533,316),v(522,402,686),v(281,426,615),v(400,406,662),v(131,523,477),v(879,499,453),v(766,520,388),v(322,427,605),v(490,393,683),v(314,427,617),v(708,529,359),v(239,435,594),v(493,600,241),v(759,519,388),v(230,457,570),v(552,572,261),v(735,524,385),v(297,439,610),v(510,594,239),v(927,495,481),v(489,400,668),v(576,571,281),v(784,517,402),v(476,607,241),v(793,505,403),v(634,381,727),v(554,384,715),v(589,383,721),v(520,388,695),v(963,501,501),v(915,497,473),v(960,502,499),v(778,517,399),v(670,519,328),v(549,581,272),v(688,523,340),v(342,557,358),v(666,545,330),v(637,542,313),v(748,519,386),v(245,435,604),v(347,433,618),v(525,586,248),v(758,518,387),v(261,429,617),v(787,511,400),v(642,549,317),v(747,512,384),v(568,574,280),v(287,458,579),v(255,435,606),v(713,526,361),v(910,497,469),v(503,399,682),v(691,526,347),v(311,434,610),v(707,537,355),v(838,508,436),v(852,503,438),v(252,433,617),v(320,436,631),v(538,577,257),v(315,426,625),v(918,498,474),v(546,581,276),v(635,542,327),v(578,384,714),v(508,397,691),v(820,505,418),v(483,606,226),v(658,534,328),v(293,431,609),v(509,407,687),v(296,426,627),v(523,587,246),v(723,513,360),v(553,570,262),v(728,517,364),v(591,564,287),v(761,520,385),v(437,414,658),v(239,443,590),v(349,422,640),v(899,497,466),v(602,556,291),v(417,404,662),v(800,515,414),v(277,429,610),v(619,557,302),v(221,437,601),v(446,628,210),v(325,425,629),v(300,428,617),v(613,549,301),v(486,392,692),v(806,495,411),v(173,445,582),v(371,420,642),v(554,383,714),v(521,588,244),v(421,406,662),v(573,382,710),v(941,497,489),v(285,431,600),v(483,563,319),v(779,501,397),v(935,501,485),v(683,371,750),v(900,495,467),v(580,383,723),v(328,421,628),v(574,563,273),v(275,439,580),v(542,386,700),v(583,385,716),v(655,550,324),v(719,517,359),v(572,402,643),v(290,435,605),v(255,451,585),v(866,505,451),v(751,521,386),v(537,395,696),v(699,514,345),v(271,428,620),v(386,420,621),v(757,522,382),v(323,427,621),v(537,583,257),v(276,427,626),v(686,529,350),v(614,557,303),v(844,501,432),v(254,432,600),v(596,553,285),v(182,458,557),v(269,432,608),v(325,427,623),v(652,548,324),v(958,502,499),v(917,497,474),v(532,403,682),v(342,425,612),v(674,543,338),v(784,512,397),v(691,531,357),v(514,594,248),v(470,396,671),v(591,559,287),v(504,397,679),v(291,438,609),v(708,530,355),v(957,501,497),v(608,494,494),v(279,438,595),v(720,370,762),v(253,435,575),v(570,569,275),v(292,428,626),v(355,435,622),v(638,508,402),v(289,427,625),v(248,456,585),v(643,541,321),v(857,505,444),v(661,548,329),v(382,414,648),v(490,601,249),v(656,536,328),v(553,577,267),v(495,602,234),v(375,414,634),v(304,431,612),v(692,538,346),v(569,563,269),v(833,506,429),v(282,430,620),v(964,501,501),v(698,535,347),v(462,616,222),v(420,421,653),v(324,426,619),v(298,430,598),v(554,393,699),v(462,399,681),v(779,517,402),v(778,515,400),v(908,501,470),v(282,430,615),v(555,570,263),v(300,433,613),v(439,405,667),v(857,499,441),v(486,604,227),v(478,398,675),v(647,543,319),v(658,540,334),v(864,504,443),v(177,464,562),v(321,428,618),v(946,496,492),v(670,543,332),v(506,393,695),v(671,529,335),v(561,572,269),v(765,516,389),v(820,502,419),v(369,418,627),v(622,552,307),v(311,427,619),v(131,509,495),v(420,637,209),v(296,441,612),v(258,439,611),v(645,383,721),v(311,424,629),v(736,520,371),v(907,495,468),v(782,517,410),v(534,582,253),v(700,537,350),v(417,431,647),v(251,434,600),v(210,466,553),v(542,584,265),v(275,431,603),v(647,532,313),v(794,512,401),v(275,432,620),v(585,558,284),v(754,517,377),v(635,382,728),v(694,542,351),v(727,506,364),v(602,377,727),v(417,420,648),v(167,492,525),v(564,384,710),v(862,502,445),v(245,437,594),v(439,632,208),v(250,436,600),v(606,377,736),v(438,406,661),v(294,439,619),v(474,456,497),v(493,391,690),v(517,590,240),v(516,591,246),v(526,586,250),v(286,427,623),v(794,515,414),v(610,556,296),v(263,443,569),v(572,573,279),v(460,428,650),v(662,539,347),v(265,433,600),v(562,574,266),v(597,552,283),v(280,428,626),v(799,515,407),v(478,395,681),v(524,588,246),v(951,498,493),v(444,415,665),v(762,473,464),v(929,496,483),v(517,392,691),v(930,503,481),v(480,398,686),v(428,405,657),v(220,450,582),v(313,453,536),v(264,450,560),v(527,586,252),v(319,501,454),v(580,560,278),v(594,381,723),v(560,390,700),v(725,524,367),v(665,369,752),v(287,428,625),v(528,585,245),v(652,537,320),v(765,519,388),v(588,556,283),v(545,577,262),v(683,525,337),v(697,533,354),v(252,451,603),v(552,578,264),v(518,390,701),v(624,549,307),v(719,527,360),v(317,434,594),v(818,493,419),v(628,544,307),v(247,449,582),v(668,531,332),v(612,382,727),v(860,506,448),v(823,507,420),v(721,532,360),v(478,398,671),v(626,383,724),v(458,622,213),v(486,604,227),v(649,397,653),v(613,543,295),v(276,440,576),v(484,604,240),v(501,401,674),v(278,433,612),v(400,409,649),v(659,549,333),v(676,534,339),v(681,534,338),v(578,569,280),v(760,509,383),v(736,525,373),v(302,426,623),v(661,399,717),v(395,418,631),v(444,540,385),v(271,434,608),v(583,569,288),v(914,493,474),v(486,606,225),v(678,490,427),v(870,501,448),v(481,400,668),v(685,541,341),v(952,499,494),v(596,555,286),v(736,527,370),v(280,432,626));
    const vec2 POSITIONS[COUNT] = vec2[](u(502,835),u(402,153),u(825,131),u(977,577),u(293,440),u(95,527),u(903,954),u(587,471),u(212,825),u(826,178),u(128,206),u(742,697),u(839,569),u(590,208),u(158,654),u(169,397),u(978,347),u(396,573),u(767,390),u(796,614),u(894,851),u(38,91),u(79,939),u(596,265),u(527,716),u(141,686),u(658,953),u(640,443),u(602,60),u(773,475),u(976,59),u(722,967),u(379,963),u(555,560),u(498,625),u(464,211),u(837,896),u(324,736),u(930,394),u(891,721),u(395,930),u(256,126),u(524,424),u(166,252),u(329,934),u(859,410),u(365,333),u(217,942),u(735,515),u(586,925),u(741,301),u(809,846),u(178,974),u(630,12),u(39,919),u(980,442),u(25,289),u(115,934),u(453,985),u(768,120),u(416,430),u(402,547),u(907,164),u(18,178),u(548,662),u(462,119),u(749,989),u(85,483),u(772,450),u(628,804),u(898,359),u(722,625),u(294,323),u(229,171),u(953,806),u(727,220),u(207,479),u(18,402),u(598,156),u(178,184),u(245,33),u(640,530),u(334,483),u(966,714),u(212,540),u(922,443),u(693,624),u(299,752),u(353,214),u(938,385),u(773,652),u(476,459),u(858,521),u(63,219),u(357,345),u(100,162),u(957,690),u(183,416),u(566,891),u(804,9),u(699,935),u(858,317),u(939,865),u(341,983),u(652,416),u(65,952),u(986,899),u(600,515),u(93,717),u(292,326),u(915,58),u(97,321),u(777,582),u(113,96),u(254,469),u(166,634),u(945,730),u(455,436),u(433,12),u(685,880),u(920,105),u(28,536),u(579,173),u(632,308),u(535,562),u(236,690),u(291,978),u(670,584),u(305,274),u(716,577),u(792,446),u(328,747),u(599,588),u(516,332),u(823,924),u(27,795),u(845,190),u(954,258),u(536,856),u(372,615),u(869,365),u(584,375),u(631,989),u(735,131),u(366,176),u(749,919),u(439,895),u(414,749),u(891,143),u(481,477),u(682,503),u(439,185),u(453,483),u(211,767),u(560,75),u(650,748),u(950,168),u(23,246),u(787,283),u(106,67),u(566,804),u(71,441),u(992,764),u(932,577),u(182,176),u(614,213),u(925,536),u(702,433),u(30,45),u(293,739),u(566,621),u(956,665),u(453,172),u(334,57),u(747,448),u(243,635),u(987,221),u(719,100),u(147,283),u(74,172),u(843,858),u(497,939),u(726,373),u(703,327),u(478,162),u(571,575),u(65,148),u(657,860),u(908,500),u(187,205),u(129,880),u(906,432),u(353,191),u(387,825),u(809,570),u(255,458),u(576,826),u(798,951),u(808,920),u(152,618),u(162,446),u(32,356),u(188,310),u(843,267),u(155,948),u(752,662),u(501,608),u(823,538),u(32,693),u(609,960),u(145,668),u(940,385),u(481,893),u(488,553),u(430,474),u(806,85),u(688,189),u(266,893),u(953,479),u(952,20),u(800,643),u(901,745),u(301,475),u(537,978),u(930,210),u(57,235),u(442,632),u(228,750),u(398,403),u(417,488),u(224,143),u(950,880),u(814,436),u(925,928),u(143,11),u(874,96),u(39,988),u(172,108),u(681,579),u(775,926),u(551,638),u(426,299),u(762,247),u(92,968),u(930,761),u(737,493),u(259,158),u(827,229),u(492,44),u(657,674),u(109,639),u(900,629),u(215,610),u(489,825),u(526,893),u(904,220),u(193,223),u(511,216),u(965,925),u(478,650),u(540,251),u(690,451),u(722,95),u(606,780),u(969,134),u(806,824),u(373,108),u(328,123),u(42,953),u(201,329),u(46,474),u(363,136),u(373,200),u(310,307),u(281,837),u(604,238),u(534,292),u(877,892),u(750,163),u(3,446),u(131,481),u(855,459),u(52,408),u(878,925),u(244,361),u(354,237),u(354,698),u(599,422),u(604,328),u(653,282),u(888,840),u(275,508),u(140,465),u(128,137),u(257,204),u(596,475),u(608,551),u(929,243),u(54,646),u(639,86),u(331,461),u(863,838),u(419,131),u(536,783),u(30,28),u(559,463),u(336,954),u(991,708),u(860,107),u(224,730),u(24,200),u(689,117),u(525,132),u(593,865),u(923,448),u(342,982),u(258,419),u(590,402),u(519,950),u(147,918),u(662,475),u(943,833),u(889,287),u(799,630),u(470,386),u(813,182),u(196,910),u(803,600),u(768,408),u(861,170),u(12,408),u(953,361),u(245,920),u(605,36),u(964,202),u(526,447),u(403,53),u(833,199),u(695,539),u(861,521),u(568,989),u(56,281),u(658,975),u(536,506),u(392,907),u(879,791),u(771,341),u(59,124),u(429,946),u(103,847),u(836,964),u(790,49),u(741,675),u(952,709),u(667,828),u(769,211),u(597,185),u(780,358),u(302,395),u(261,426),u(496,478),u(731,551),u(707,983),u(276,222),u(271,771),u(684,158),u(223,276),u(189,918),u(825,729),u(558,356),u(134,901),u(638,563),u(352,479),u(115,224),u(335,149),u(885,987),u(479,876),u(25,320),u(858,476),u(112,988),u(882,570),u(200,613),u(956,319),u(686,626),u(428,216),u(64,183),u(727,898),u(686,197),u(847,25),u(446,321),u(343,18),u(872,567),u(107,945),u(856,434),u(201,886),u(328,973),u(381,161),u(972,105),u(76,203),u(623,899),u(14,120),u(111,706),u(931,726),u(858,34),u(607,604),u(258,747),u(168,432),u(713,934),u(80,589),u(202,348),u(533,208),u(185,191),u(450,353),u(610,565),u(771,134),u(739,845),u(230,123),u(91,362),u(412,414),u(579,187),u(309,469),u(387,280),u(828,672),u(973,776),u(698,669),u(756,47),u(956,423),u(825,642),u(841,385),u(603,826),u(119,113),u(971,418),u(983,162),u(546,710),u(121,786),u(127,38),u(922,875),u(702,257),u(555,741),u(14,968),u(664,217),u(144,466),u(777,973),u(521,356),u(596,478),u(135,297),u(700,347),u(424,192),u(534,443),u(776,402),u(365,884),u(892,385),u(967,624),u(236,311),u(177,458),u(805,514),u(95,383),u(311,70),u(327,789),u(223,723),u(462,604),u(320,701),u(230,968),u(259,570),u(681,540),u(785,190),u(420,869),u(445,315),u(98,987),u(977,625),u(464,448),u(25,458),u(447,592),u(74,213),u(380,535),u(311,369),u(671,471),u(451,951),u(540,853),u(969,276),u(99,414),u(768,793),u(871,735),u(62,453),u(116,748),u(694,404),u(922,863),u(333,417),u(624,127),u(436,252),u(813,879),u(971,513),u(895,600),u(911,731),u(202,486),u(727,636),u(865,69),u(609,249),u(372,450),u(986,385),u(134,233),u(522,969),u(961,978),u(728,732),u(338,469),u(527,587),u(617,352),u(583,950),u(955,882),u(262,727),u(531,822),u(134,51));
    const mat2 COVARIANCES[COUNT] = mat2[](m(43,-38,-38,41),m(29,-5,-5,22),m(18,2,2,33),m(17,2,2,33),m(215,-17,-17,5),m(103,-20,-20,23),m(92,-10,-10,15),m(86,-24,-24,24),m(130,-73,-73,88),m(188,-114,-114,69),m(19,2,2,6),m(43,-1,-1,1),m(20,7,7,16),m(99,2,2,6),m(86,-27,-27,10),m(169,-31,-31,14),m(23,2,2,8),m(39,-17,-17,22),m(109,-33,-33,13),m(117,-7,-7,3),m(19,20,20,57),m(40,10,10,21),m(32,-18,-18,19),m(295,-12,-12,6),m(129,-70,-70,73),m(181,-15,-15,7),m(35,9,9,18),m(18,0,0,2),m(128,-17,-17,123),m(107,2,2,2),m(24,-1,-1,18),m(133,-71,-71,43),m(10,-6,-6,14),m(23,0,0,2),m(62,-5,-5,4),m(80,-7,-7,5),m(26,23,23,59),m(16,-23,-23,37),m(37,1,1,3),m(6,0,0,23),m(56,-7,-7,12),m(286,0,0,30),m(57,-18,-18,16),m(312,-36,-36,25),m(23,-7,-7,16),m(318,-13,-13,5),m(216,-38,-38,43),m(47,-20,-20,31),m(55,-5,-5,7),m(44,-17,-17,15),m(305,13,13,7),m(45,-40,-40,46),m(14,-13,-13,22),m(671,40,40,7),m(31,-8,-8,12),m(11,4,4,22),m(27,3,3,31),m(28,40,40,77),m(31,-5,-5,10),m(179,15,15,47),m(175,-36,-36,9),m(5,-1,-1,0),m(18,13,13,43),m(10,0,0,3),m(407,-97,-97,35),m(142,13,13,69),m(50,5,5,5),m(30,0,0,15),m(40,8,8,11),m(10,-8,-8,111),m(27,3,3,1),m(68,-12,-12,207),m(538,-54,-54,29),m(360,34,34,5),m(74,8,8,30),m(44,5,5,3),m(569,71,71,10),m(12,-8,-8,64),m(520,45,45,23),m(309,9,9,0),m(57,-5,-5,27),m(224,-36,-36,7),m(35,0,0,1),m(40,-6,-6,11),m(149,-12,-12,26),m(133,62,62,56),m(78,6,6,7),m(3,-1,-1,7),m(139,-2,-2,5),m(137,-12,-12,1),m(162,-56,-56,78),m(297,-35,-35,5),m(22,-17,-17,69),m(156,9,9,2),m(111,-6,-6,3),m(228,19,19,2),m(88,1,1,4),m(128,-8,-8,3),m(11,-8,-8,36),m(453,7,7,4),m(11,-27,-27,116),m(185,-28,-28,14),m(128,-23,-23,7),m(35,-15,-15,17),m(75,-20,-20,6),m(87,5,5,50),m(8,0,0,39),m(157,-43,-43,18),m(39,-11,-11,4),m(99,7,7,10),m(37,-3,-3,8),m(50,-1,-1,21),m(44,-10,-10,35),m(148,10,10,11),m(150,1,1,0),m(40,-20,-20,18),m(36,9,9,7),m(75,-25,-25,12),m(391,27,27,5),m(34,-27,-27,66),m(59,14,14,17),m(32,-6,-6,45),m(314,15,15,2),m(114,-11,-11,8),m(72,-7,-7,12),m(64,-28,-28,43),m(31,-17,-17,20),m(5,-1,-1,18),m(108,-22,-22,11),m(11,-14,-14,47),m(31,29,29,38),m(13,-13,-13,17),m(177,-82,-82,42),m(213,11,11,31),m(15,-3,-3,28),m(30,-5,-5,207),m(682,18,18,2),m(77,-36,-36,18),m(52,-14,-14,9),m(159,-5,-5,48),m(205,-18,-18,13),m(151,-24,-24,7),m(27,0,0,4),m(105,16,16,3),m(225,17,17,3),m(73,-47,-47,37),m(17,-12,-12,30),m(148,-71,-71,69),m(70,5,5,29),m(56,0,0,2),m(95,-19,-19,23),m(16,10,10,91),m(23,8,8,6),m(27,4,4,2),m(19,4,4,74),m(89,72,72,113),m(21,3,3,27),m(34,4,4,9),m(205,5,5,6),m(386,24,24,4),m(32,-32,-32,41),m(115,13,13,6),m(3,0,0,27),m(16,3,3,21),m(1007,87,87,8),m(36,11,11,8),m(142,-14,-14,21),m(232,-37,-37,11),m(44,0,0,19),m(86,-40,-40,33),m(108,-56,-56,37),m(105,-1,-1,13),m(41,7,7,3),m(165,5,5,18),m(62,-1,-1,23),m(139,-89,-89,71),m(7,57,57,476),m(1982,189,189,101),m(95,-51,-51,41),m(162,15,15,2),m(19,5,5,6),m(74,-44,-44,38),m(745,-145,-145,37),m(110,-38,-38,24),m(136,39,39,21),m(46,-30,-30,39),m(132,11,11,2),m(99,-70,-70,58),m(35,0,0,13),m(89,0,0,4),m(46,-7,-7,5),m(41,-12,-12,15),m(62,6,6,2),m(379,-176,-176,100),m(306,12,12,48),m(158,-18,-18,3),m(33,-20,-20,15),m(44,5,5,6),m(30,8,8,8),m(78,-72,-72,72),m(115,2,2,0),m(41,-17,-17,16),m(86,-23,-23,11),m(272,-20,-20,5),m(8,-4,-4,16),m(56,9,9,14),m(19,5,5,22),m(101,12,12,6),m(34,-20,-20,42),m(10,-4,-4,19),m(125,-26,-26,6),m(66,-7,-7,2),m(140,-53,-53,24),m(57,-11,-11,11),m(779,-74,-74,9),m(161,12,12,4),m(91,21,21,6),m(140,38,38,19),m(64,9,9,8),m(80,-1,-1,13),m(20,-17,-17,32),m(6,-4,-4,7),m(124,-7,-7,0),m(26,-18,-18,19),m(166,14,14,3),m(90,9,9,12),m(136,32,32,12),m(12,0,0,1),m(27,-1,-1,10),m(54,0,0,3),m(57,-6,-6,4),m(99,-87,-87,87),m(15,7,7,17),m(34,-3,-3,7),m(469,20,20,5),m(471,-80,-80,254),m(26,-7,-7,9),m(222,-41,-41,22),m(22,-6,-6,26),m(99,-15,-15,15),m(34,4,4,185),m(171,5,5,9),m(225,24,24,12),m(184,-26,-26,13),m(115,-21,-21,10),m(569,-44,-44,8),m(438,26,26,4),m(133,8,8,2),m(146,-10,-10,50),m(89,17,17,55),m(69,-60,-60,59),m(99,0,0,5),m(7,1,1,53),m(42,-30,-30,28),m(32,-9,-9,9),m(271,25,25,5),m(129,4,4,3),m(94,-32,-32,49),m(28,27,27,46),m(52,-4,-4,3),m(75,43,43,98),m(60,-22,-22,36),m(12,25,25,158),m(23,-24,-24,32),m(69,5,5,89),m(78,-69,-69,76),m(125,28,28,11),m(60,53,53,64),m(40,17,17,56),m(71,2,2,8),m(39,-3,-3,10),m(8,6,6,9),m(409,4,4,0),m(28,5,5,7),m(111,-45,-45,47),m(182,6,6,5),m(244,13,13,9),m(15,-1,-1,7),m(339,0,0,12),m(0,0,0,0),m(35,2,2,4),m(163,-8,-8,3),m(32,-4,-4,6),m(96,-80,-80,81),m(80,-8,-8,7),m(312,-19,-19,9),m(315,-51,-51,60),m(106,-26,-26,8),m(147,-12,-12,7),m(203,3,3,4),m(196,24,24,18),m(332,8,8,12),m(46,4,4,0),m(75,9,9,8),m(67,-16,-16,6),m(33,-1,-1,8),m(141,18,18,15),m(126,-4,-4,8),m(70,-18,-18,22),m(15,0,0,47),m(218,-14,-14,1),m(19,0,0,12),m(178,-24,-24,24),m(174,-76,-76,36),m(40,0,0,23),m(74,-29,-29,20),m(41,-32,-32,31),m(2,0,0,2),m(31,-20,-20,18),m(69,-18,-18,7),m(16,-2,-2,6),m(25,-8,-8,13),m(44,8,8,13),m(8,0,0,29),m(171,55,55,21),m(14,-5,-5,9),m(31,-4,-4,3),m(44,-3,-3,5),m(38,-23,-23,21),m(55,-18,-18,8),m(240,-54,-54,30),m(104,6,6,3),m(105,-2,-2,10),m(209,-21,-21,4),m(104,8,8,13),m(115,15,15,5),m(294,13,13,5),m(166,-3,-3,10),m(743,-128,-128,22),m(65,3,3,7),m(6,-4,-4,20),m(26,1,1,2),m(16,3,3,23),m(172,32,32,12),m(55,1,1,4),m(207,-31,-31,4),m(30,-19,-19,38),m(131,10,10,1),m(51,-7,-7,3),m(20,-1,-1,3),m(25,0,0,5),m(47,-2,-2,12),m(24,4,4,12),m(100,-11,-11,14),m(45,-12,-12,6),m(48,-35,-35,44),m(135,-21,-21,6),m(29,0,0,7),m(96,-79,-79,73),m(284,-161,-161,142),m(21,-22,-22,28),m(35,-10,-10,29),m(16,1,1,7),m(57,24,24,17),m(26,-3,-3,20),m(146,11,11,2),m(984,3,3,0),m(7,11,11,27),m(256,-26,-26,9),m(78,-7,-7,8),m(27,-7,-7,6),m(31,-9,-9,38),m(3,-2,-2,10),m(78,-16,-16,16),m(18,4,4,5),m(298,14,14,10),m(183,-44,-44,19),m(5,-4,-4,11),m(90,-9,-9,46),m(223,-61,-61,20),m(140,-14,-14,7),m(32,-26,-26,41),m(200,-15,-15,3),m(303,-76,-76,28),m(212,2,2,4),m(91,-3,-3,7),m(11,-3,-3,11),m(25,-5,-5,11),m(57,0,0,3),m(12,-1,-1,6),m(33,18,18,13),m(9,7,7,16),m(77,-14,-14,20),m(7,-4,-4,30),m(57,17,17,39),m(32,4,4,2),m(81,-20,-20,17),m(533,15,15,1),m(328,28,28,14),m(250,-5,-5,26),m(503,50,50,10),m(3,-5,-5,29),m(181,-24,-24,34),m(54,-10,-10,24),m(60,8,8,5),m(31,-20,-20,15),m(6088,353,353,32),m(13,3,3,20),m(36,6,6,7),m(42,-20,-20,25),m(7,0,0,27),m(28,4,4,4),m(33,13,13,22),m(50,4,4,4),m(67,-10,-10,8),m(103,-6,-6,5),m(311,1,1,3),m(7,8,8,19),m(219,-51,-51,43),m(241,-56,-56,44),m(77,-2,-2,4),m(352,5,5,1),m(237,-63,-63,31),m(11,-8,-8,10),m(23,20,20,34),m(42,14,14,25),m(1037,110,110,13),m(241,-82,-82,39),m(121,-16,-16,8),m(20,7,7,7),m(254,-11,-11,0),m(468,-86,-86,22),m(160,-65,-65,37),m(15,17,17,27),m(8,6,6,7),m(760,73,73,12),m(50,-27,-27,35),m(8,-2,-2,11),m(361,-53,-53,8),m(31,33,33,62),m(350,-161,-161,200),m(52,11,11,3),m(9,7,7,38),m(33,-11,-11,13),m(153,-60,-60,31),m(323,9,9,11),m(19,-7,-7,44),m(59,7,7,6),m(51,-15,-15,21),m(7,-1,-1,8),m(65,1,1,6),m(329,33,33,3),m(100,16,16,8),m(23,14,14,28),m(19,-4,-4,2),m(204,23,23,16),m(266,-92,-92,35),m(413,4,4,0),m(731,-105,-105,15),m(1017,-173,-173,29),m(193,-64,-64,41),m(327,-55,-55,9),m(48,18,18,13),m(115,-48,-48,23),m(128,0,0,1),m(158,-49,-49,21),m(141,-17,-17,8),m(1662,89,89,88),m(52,-11,-11,30),m(50,-31,-31,33),m(20,-19,-19,28),m(29,-29,-29,56),m(124,-56,-56,45),m(45,-21,-21,46),m(36,25,25,26),m(96,31,31,11),m(45,-27,-27,39),m(189,-21,-21,30),m(216,0,0,5),m(15,-5,-5,5),m(184,-28,-28,5),m(34,0,0,2),m(15,-9,-9,11),m(33,16,16,17),m(277,-74,-74,45),m(265,-16,-16,8),m(84,-15,-15,6),m(118,-95,-95,84),m(24,-33,-33,274),m(38,-6,-6,18),m(23,-3,-3,5),m(137,-13,-13,30),m(10,-3,-3,84),m(60,12,12,2),m(173,-54,-54,84),m(59,-13,-13,7),m(0,-3,-3,139),m(55,-5,-5,6),m(175,22,22,12),m(432,-22,-22,5),m(17,7,7,24),m(23,-4,-4,24),m(40,0,0,8),m(18,18,18,26),m(101,-5,-5,5),m(186,61,61,58),m(461,38,38,6),m(55,68,68,169),m(100,-8,-8,1),m(8,1,1,6),m(47,4,4,2),m(67,-52,-52,45),m(51,0,0,13),m(98,2,2,31),m(260,-14,-14,1),m(16,7,7,11),m(49,-10,-10,10),m(12,-12,-12,22),m(10,0,0,5),m(21,5,5,67),m(22,-22,-22,35),m(49,-7,-7,16));

    // Define the struct to store the cluster data
    struct clusters {int weight[COUNT]; vec3 colors[COUNT]; vec2 centers[COUNT]; mat2 covariances[COUNT];};

    // Struct holding the information for the image
    clusters getClusters() { 
        return clusters(WEIGHTS, COLORS, POSITIONS, COVARIANCES); 
    }

    // Computes the probability density function of a multivariate Gaussian
    #define TWO_PI 6.28318530718
    float multivariateGaussian(vec2 x, vec2 center, mat2 covariance) {
        mat2 cov_inv = inverse(covariance);
        float cov_det = determinant(covariance);
        if (cov_det <= 0.0) return 0.0;
        float norm_factor = sqrt(TWO_PI * TWO_PI * cov_det);
        vec2 diff = x - center;
        float exponent = -0.5 * dot(diff * cov_inv, diff);
        float pdf_value = exp(exponent) / norm_factor;
        return max(1.e-06, pdf_value); // prevent rounding errors
    }

    // Calculates color for a given point across Gaussian clustering
    vec3 calculateColors(vec2 uv, clusters data) {
        float probabilitySum = 0.0;
        vec3 color = vec3(0.0);

        // Loop over the radiusxradius grid of cells around the current cell
        int radius = int(TILING); // either 0 or 1
        for (int offsetX = -radius; offsetX <= radius; offsetX++) {
        for (int offsetY = -radius; offsetY <= radius; offsetY++) {

            for (int k = 0; k < COUNT; k++) {
                vec2 clusterCenter = data.centers[k] * SCALES.y + vec2(offsetX, offsetY);
                float pdf = multivariateGaussian(uv, clusterCenter, data.covariances[k] * SCALES.w);
                float probability = float(data.weight[k]) * SCALES.x * pdf;
                color += data.colors[k] * SCALES.z * probability;
                probabilitySum += probability;
            }
        }
        }

        // Normalize the final color by the total weight sum
        if (probabilitySum > 0.0) {
            color /= probabilitySum;
        }
        return color;
    }

    vec3 normalizedLabToLab(vec3 labNorm) {
        return vec3(labNorm.x * 100.0,			// L in [0, 100]
                    labNorm.y * 255.0 - 128.0,  // a in [-128, 127]
                    labNorm.z * 255.0 - 128.0); // b in [-128, 127]
    }

    vec3 labToXyz(vec3 lab) {
        float fy = (lab.x + 16.0) / 116.0;
        float fx = lab.y / 500.0 + fy;
        float fz = fy - lab.z / 200.0;

        float xr = (fx > 0.206897) ? pow(fx, 3.0) : (fx - 16.0 / 116.0) / 7.787;
        float yr = (lab.x > 7.9996) ? pow(fy, 3.0) : lab.x / 903.3;
        float zr = (fz > 0.206897) ? pow(fz, 3.0) : (fz - 16.0 / 116.0) / 7.787;

        return vec3(xr * 95.047, yr * 100.000, zr * 108.883);
    }

    vec3 xyzToRgb(vec3 xyz) {	
        xyz /= 100.0; // sRGB D65 matrix transformation

        vec3 rgb = vec3(xyz.x *  3.2406 + xyz.y * -1.5372 + xyz.z * -0.4986,
                        xyz.x * -0.9689 + xyz.y *  1.8758 + xyz.z *  0.0415,
                        xyz.x *  0.0557 + xyz.y * -0.2040 + xyz.z *  1.0570);

        // Apply gamma correction (sRGB)
        rgb = mix(rgb * 12.92, pow(rgb, vec3(1.0 / 2.4)) * 1.055 - 0.055, step(0.0031308, rgb));

        return clamp(rgb, 0.0, 1.0);
    }

    vec3 normalizedLabToRgb(vec3 labNorm) {
        return xyzToRgb(labToXyz(normalizedLabToLab(labNorm)));
    }

    // hash by David Hoskins https://www.shadertoy.com/view/XdGfRR
    #define FPRIME 2800852409U
    #define VPRIME uvec2(3480082861U, 2420690917U)
    #define SMALLESTFLOAT (1.0 / float(0xffffffffU))
    float hash12(vec2 p) {
        uvec2 q = uvec2(ivec2(p)) * VPRIME;
        uint n = (q.x ^ q.y) * FPRIME;
        return float(n) * SMALLESTFLOAT;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {

        // Get the hash for the previous frame from the corner of the buffer
        float previousHash = texelFetch(iChannel0, ivec2(0), 0).w;	

        // Compute a hash for the current resolution
        float hash = hash12(iResolution.xy);

        // Initialization: check if resolution changed or uninitialized
        if (abs(previousHash - hash) > 0.0001 || iFrame < 10) {

            // centered UVs of custom aspect ratio 16x9
            vec2 resolution = iResolution.x > iResolution.y ? iResolution.y * vec2(16./9.,1) : 
                                                              iResolution.x * vec2(1,9./16.);
            vec2 uv = (fragCoord - iResolution.xy * 0.5) / resolution + 0.5;

            // zoom out a tiny bit becasue I like the out of bounds areas
            //uv = (uv-0.5) * 1.5 + 0.5; 

            // generate Image form clustering data
            vec3 color = normalizedLabToRgb(calculateColors(uv, getClusters()));

            // Set the color to the Buffer
            fragColor = vec4(color, 1);

        } else {
            // Sample buffer itself
            fragColor = texelFetch(iChannel0, ivec2(fragCoord),0);
        }

        // Store the current resolution hash in the corner of the buffer
        if (ivec2(fragCoord) == ivec2(0)) {
            fragColor.w = hash;
        }
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

    src_static = """
    /////////////////// static music

    void mainImage( out vec4 O, in vec2 fragCoord )
    {

        vec2 u =  fragCoord/iResolution.xy;
        for(int i;i++<17;)
        {
             //u+=tan(mod(exp(sin(u.x+u.y)),atan(u.x,u.y+u.x)))*abs(u.x-u.y)+.001;
             u+=tan(mod(sin(u.x+u.y),atan(u.x,u.y+u.x)))*sin(abs(u.x-u.y))+.001;
        }

        O.xy=u  *.3 ;
        O.z=0.;//1.-mod(u.x,u.y)*.2;
    }
    """

    src_galaxy = """
    // By Jared Berghold 2022 (https://www.jaredberghold.com/)
    // Based on the "Simplicity Galaxy" shader by CBS (https://www.shadertoy.com/view/MslGWN) 
    // The nebula effect is based on the kaliset fractal (https://softologyblog.wordpress.com/2011/05/04/kalisets-and-hybrid-ducks/)

    const int MAX_ITER = 18;

    float field(vec3 p, float s, int iter)
    {
        float accum = s / 4.0;
        float prev = 0.0;
        float tw = 0.0;
        for (int i = 0; i < MAX_ITER; ++i) 
        {
            if (i >= iter) // drop from the loop if the number of iterations has been completed - workaround for GLSL loop index limitation
            {
                break;
            }
            float mag = dot(p, p);
            p = abs(p) / mag + vec3(-0.5, -0.4, -1.487);
            float w = exp(-float(i) / 5.0);
            accum += w * exp(-9.025 * pow(abs(mag - prev), 2.2));
            tw += w;
            prev = mag;
        }
        return max(0.0, 5.2 * accum / tw - 0.65);
    }

    vec3 nrand3(vec2 co)
    {
        vec3 a = fract(cos(co.x*8.3e-3 + co.y) * vec3(1.3e5, 4.7e5, 2.9e5));
        vec3 b = fract(sin(co.x*0.3e-3 + co.y) * vec3(8.1e5, 1.0e5, 0.1e5));
        vec3 c = mix(a, b, 0.5);
        return c;
    }

    vec4 starLayer(vec2 p, float time)
    {
        vec2 seed = 1.9 * p.xy;
        seed = floor(seed * max(iResolution.x, 600.0) / 1.5);
        vec3 rnd = nrand3(seed);
        vec4 col = vec4(pow(rnd.y, 17.0));
        float mul = 10.0 * rnd.x;
        col.xyz *= sin(time * mul + mul) * 0.25 + 1.0;
        return col;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        float time = iTime / (iResolution.x / 1000.0);

        // first layer of the kaliset fractal
        vec2 uv = 2.0 * fragCoord / iResolution.xy - 1.0;
        vec2 uvs = uv * iResolution.xy / max(iResolution.x, iResolution.y);
        vec3 p = vec3(uvs / 2.5, 0.0) + vec3(0.8, -1.3, 0.0);
        p += 0.45 * vec3(sin(time / 32.0), sin(time / 24.0), sin(time / 64.0));

        // adjust first layer position based on mouse movement
        p.x += mix(-0.02, 0.02, (iMouse.x / iResolution.x));
        p.y += mix(-0.02, 0.02, (iMouse.y / iResolution.y));

        float freqs[4];
        freqs[0] = 0.45;
        freqs[1] = 0.4;
        freqs[2] = 0.15;
        freqs[3] = 0.9;

        float t = field(p, freqs[2], 13);
        float v = (1.0 - exp((abs(uv.x) - 1.0) * 6.0)) * (1.0 - exp((abs(uv.y) - 1.0) * 6.0));

        // second layer of the kaliset fractal
        vec3 p2 = vec3(uvs / (4.0 + sin(time * 0.11) * 0.2 + 0.2 + sin(time * 0.15) * 0.3 + 0.4), 4.0) + vec3(2.0, -1.3, -1.0);
        p2 += 0.16 * vec3(sin(time / 32.0), sin(time / 24.0), sin(time / 64.0));

        // adjust second layer position based on mouse movement
        p2.x += mix(-0.01, 0.01, (iMouse.x / iResolution.x));
        p2.y += mix(-0.01, 0.01, (iMouse.y / iResolution.y));
        float t2 = field(p2, freqs[3], 18);
        vec4 c2 = mix(0.5, 0.2, v) * vec4(5.5 * t2 * t2 * t2, 2.1 * t2 * t2, 2.2 * t2 * freqs[0], t2);

        // add stars (source: https://glslsandbox.com/e#6904.0)
        vec4 starColour = vec4(0.0);
        starColour += starLayer(p.xy, time); // add first layer of stars
        starColour += starLayer(p2.xy, time); // add second layer of stars

        const float brightness = 1.0;
        vec4 colour = mix(freqs[3] - 0.3, 1.0, v) * vec4(1.5 * freqs[2] * t * t * t, 1.2 * freqs[1] * t * t, freqs[3] * t, 1.0) + c2 + starColour;
        fragColor = vec4(brightness * colour.xyz, 1.0);
    }
    """

    src_nebula_112 = """
    float n11(float p) {
        return fract(sin(p*154.101)*313.019);
    } 
    float n21(vec2 p) {
        float n = sin(dot(p, vec2(7, 157)));    
        return n;
    }
    vec3 hash33(vec3 p){ 
        float n = sin(dot(p, vec3(7, 157, 113)));    
        return fract(vec3(2097152, 262144, 32768)*n); 
    }

    float voronoi(vec3 p){
        vec3 b, r, g = floor(p);
        p = fract(p);
        float d = 1.; 
        for(int j = -1; j <= 1; j++) {
            for(int i = -1; i <= 1; i++) {
                b = vec3(i, j, -1);
                r = b - p + hash33(g+b);
                d = min(d, dot(r,r));
                b.z = 0.0;
                r = b - p + hash33(g+b);
                d = min(d, dot(r,r));
                b.z = 1.;
                r = b - p + hash33(g+b);
                d = min(d, dot(r,r));
            }
        }

        return d; // Range: [0, 1]
    }

    vec3 hsl2rgb( in vec3 c ){
        vec3 rgb = clamp( abs(mod(c.x*6.0+vec3(0.0,4.0,2.0),6.0)-3.0)-1.0, 0.0,1.0);
        return c.z + c.y * (rgb-0.5)*(1.0-abs(2.0*c.z-1.0));
    }

    float nebula(in vec3 p) {
        float amp = 1., sum=0., z= 1., m = 0.;
        for(int i=1; i<=10;i++){
            vec3 t = vec3(0., 0., p.z+iTime*.1);
            z *= 2.;
            m += voronoi(vec3(p.xy*z, 1.)+t) *amp;
            sum += amp;
            amp *= .5;
        }
        m /= sum;
        return pow(m, 1.5);
    }

    float star(vec3 p) {
        float z = 16.;
        float t = p.z;
        vec2 gv = fract(p.xy*z)-.5;
        vec2 id = floor(p.xy*z);
        gv.x += sin(n21(id)*354.23)*.3;
        gv.y += sin(n11(n21(id))*914.19)*.3;
        float r = n11(n21(id));
        float m =  .1*n11(r)*abs(sin(p.z+r*133.12))*.4/length(gv)*.1;
        return m;
    }

    float stars(in vec3 p) {
        float z= 1., m = 0.;
        for(int i=1; i<=10;i++){
        	vec3 t = vec3(0., 0., p.z+iTime*.2);
            z *= 2.;
             m += star(vec3(p.xy*z, 1.)+t);
        }
        return m;
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = (fragCoord-.5*iResolution.xy)/iResolution.y;
        vec3 col = vec3(.0);
        
        vec3 col1 = normalize(vec3(159., 38., 106.))*nebula(vec3(uv,1.));
        vec3 col2 = normalize(vec3(106., 110., 185.))*nebula(vec3(uv,1298.));
        col += mix(col1,col2,5.);
        float m = stars(vec3(uv, iTime*2.));
        col += vec3(m);

        // Output to screen
        fragColor = vec4(col,1.0);
    }
    """

    src_mb = """
    // magic ball
    // fork https://www.shadertoy.com/view/MfBczd
    // HLSL -> GLSL https://anteru.net/blog/2016/mapping-between-HLSL-and-GLSL/

    #define float2   vec2
    #define float3   vec3
    #define float4   vec4
    #define lerp     mix
    #define atan2    atan
    #define frac     fract
    #define fmod     mod
    #define float2x2 mat2     
    #define mul(a, b) a*b 
    #define texSampl 1.
    #define Texture2DSample(iChannel0, texSampl, uv) texture(iChannel0, uv)
    #define ddx dFdx
    #define ddy dFdy
    #define saturate(oo) clamp(oo, 0.0, 1.0)

    // 100% credit to SnoopethDuckDuck https://www.shadertoy.com/view/XXyGzh
    // 100% ChatGPT rewritten from lines 16 onward
    // Prompt 1:
    /*
    How does this shaderoy GLSL code
    {{code}}
    make a thing that looks like colorful magic spells flowing though stormclouds in many directions
    */

    // Prompt 2:
    /*
    how about rewriting it nicely with readable variable names and no weird code conventions like
    while (++i < 10) { ...
    */
    float ball(float2 uv, float time){
        uv *=.16;
        float d = smoothstep(.01,2.,1.7-(length(uv)*3.4));
        float col=1.;
        float2 r = float2(1.,1.);
        float amp = .4;
        for (int i=0; i<18; i++){
            col+=(1.+cos(time)*.1)/length((1.+float(i)*dot(r,r))*sin(1.5*uv/(.5-dot(uv,uv))*1.-9.*uv.yx+time))*.2;
            r = cos(++time-22.*uv*pow(amp+=.065,float(i)))-5.*uv;
            uv+=tanh(40.*dot(uv = mul(float2x2(cos(float(i)+.02 * time - float4(0.,11.,33.,0.))),uv),uv)*cos(100.*uv.yx+time))/300.+.2*amp*uv+cos(4./exp(dot(col,col)/800.)+time)/900.;
        }

        float b = 30./(min(col,30.)+164./col)-dot(uv,uv)/250.; 
        return lerp(0.,b,d);
        //return d;
    }

    void mainImage(out vec4 fragColor, in vec2 fragCoord){
        float2 uv_0 =(2.*fragCoord-iResolution.xy)/iResolution.y;
        fragColor = ball(uv_0, .16*iTime)*float4(.2,.3,2.,1.);
    }
    """

    src_zz = """
    // Zippy Zaps

    void mainImage( out vec4 o, vec2 u )
    {
        vec2 v = iResolution.xy;
             u = .2*(u+u-v)/v.y;

        vec4 z = o = vec4(1,2,3,0);

        for (float a = .5, t = 0.16*iTime, i;
             ++i < 19.;
             o += (1. + cos(z+t))
                / length((1.+i*dot(v,v))
                       * sin(1.5*u/(.5-dot(u,u)) - 9.*u.yx + t))
             )
            v = cos(++t - 7.*u*pow(a += .03, i)) - 5.*u,
            u += tanh(40. * dot(u *= mat2(cos(i + .02*t - vec4(0,11,33,0)))
                               ,u)
                          * cos(1e2*u.yx + t)) / 2e2
               + .2 * a * u
               + cos(4./exp(dot(o,o)/1e2) + t) / 3e2;

         o = 25.6 / (min(o, 13.) + 164. / o)
           - dot(u, u) / 250.;
    }
    """

    src_sg = """
    /*
        "Singularity" by @XorDev

        I'll come back to clean up the code later.
        Feel free to code golf!

        FabriceNeyret2: -19
        dean_the_coder: -12
        iq: -4
    */

    void mainImage(out vec4 O, vec2 F)
    {
        float i,j;
        vec2 r = iResolution.xy,
             p = ( F+F - r ) / r.y / .7,
             d = vec2(-1,1),
             q = 5.*p - d, 
             c = p * mat2(1, 1, d/(.1 + 5./dot(q,q)) ),
             v = c * mat2(cos(.5*log(j=dot(c,c))+iTime*.2 + vec4(0,33,11,0))) * 5.,
             s;
       
        for(; i++<9.; s += 1.+sin(v) )
            v += .7* sin(v.yx*i+iTime) / i + .5;
            
        i = length( sin(v/.3)*.4 + c*(3.+d) );
        O = 1. - exp( -exp( c.x * vec4(.6,-.4,-1,0) )
                       /  s.xyyx
                       / ( 2. + i*i/4. - i )
                       / ( .5 + 3.5 *exp( .3*c.y - j ) )
                       / ( .03 + abs( length(p)-.7 ) )
                 );
    }

    //Original [432]
    /*
    void mainImage(out vec4 O,in vec2 F)
    {
        vec2 p=(F*2.-iResolution.xy)/(iResolution.y*.7),
        d=vec2(-1,1),
        c=p*mat2(1,1,d/(.1+5./dot(5.*p-d,5.*p-d))),
        v=c;
        v*=mat2(cos(log(length(v))+iTime*.2+vec4(0,33,11,0)))*5.;
        vec4 o=vec4(0);
        for(float i;i++<9.;o+=sin(v.xyyx)+1.)
        v+=.7*sin(v.yx*i+iTime)/i+.5;
        O=1.-exp(-exp(c.x*vec4(.6,-.4,-1,0))/o
        /(.1+.1*pow(length(sin(v/.3)*.2+c*vec2(1,2))-1.,2.))
        /(1.+7.*exp(.3*c.y-dot(c,c)))
        /(.03+abs(length(p)-.7))*.2);
    }*/
    """

    src_sunset = """
    /////////////////// Sunset
    /*
        "Sunset" by @XorDev
        
        Expanded and clarified version of my Sunset shader:
        https://www.shadertoy.com/view/wXjSRt
        
        Based on my tweet shader:
        https://x.com/XorDev/status/1918764164153049480
    */

    //Output image brightness
    #define BRIGHTNESS 1.0

    //Base brightness (higher = brighter, less saturated)
    #define COLOR_BASE 1.5
    //Color cycle speed (radians per second)
    #define COLOR_SPEED 0.5
    //RGB color phase shift (in radians)
    #define RGB vec3(0.0, 1.0, 2.0)
    //Color translucency strength
    #define COLOR_WAVE 14.0
    //Color direction and (magnitude = frequency)
    #define COLOR_DOT vec3(1,-1,0)

    //Wave iterations (higher = slower)
    #define WAVE_STEPS 8.0
    //Starting frequency
    #define WAVE_FREQ 5.0
    //Wave amplitude
    #define WAVE_AMP 0.6
    //Scaling exponent factor
    #define WAVE_EXP 1.8
    //Movement direction
    #define WAVE_VELOCITY vec3(0.2)


    //Cloud thickness (lower = denser)
    #define PASSTHROUGH 0.2

    //Cloud softness
    #define SOFTNESS 0.005
    //Raymarch step
    #define STEPS 100.0
    //Sky brightness factor (finicky)
    #define SKY 10.0
    //Camera fov ratio (tan(fov_y/2))
    #define FOV 1.0

    void mainImage(out vec4 fragColor, in vec2 fragCoord)
    {
        //Raymarch depth
        float z = 0.0;
        
        //Step distance
        float d = 0.0;
        //Signed distance
        float s = 0.0;
        
        //Ray direction
        vec3 dir = normalize( vec3(2.0*fragCoord - iResolution.xy, - FOV * iResolution.y));
        
        //Output color
        vec3 col = vec3(0);
        
        //Clear fragcolor and raymarch with 100 iterations
        for(float i = 0.0; i<STEPS; i++)
        {
            //Compute raymarch sample point
            vec3 p = z * dir;
            
            //Turbulence loop
            //https://www.shadertoy.com/view/3XXSWS
            for(float j = 0.0, f = WAVE_FREQ; j<WAVE_STEPS; j++, f *= WAVE_EXP)
                
                p += WAVE_AMP*sin(p*f - WAVE_VELOCITY*iTime).yzx / f;
                
            //Compute distance to top and bottom planes
            s = 0.3 - abs(p.y);
            //Soften and scale inside the clouds
            d = SOFTNESS + max(s, -s*PASSTHROUGH) / 4.0;
            //Step forward
            z += d;
            //Coloring with signed distance, position and cycle time
            float phase = COLOR_WAVE * s + dot(p,COLOR_DOT) + COLOR_SPEED*iTime;
            //Apply RGB phase shifts, add base brightness and correct for sky
            col += (cos(phase - RGB) + COLOR_BASE) * exp(s*SKY) / d;
        }
        //Tanh tonemapping
        //https://www.shadertoy.com/view/ms3BD7
        col *= SOFTNESS / STEPS * BRIGHTNESS;
        fragColor = vec4(tanh(col * col), 1.0);
    }
    """

    src_waveform = """
    /*
        "Waveform" by @XorDev
        I wish Soundcloud worked on ShaderToy again
    */
    void mainImage(out vec4 O, vec2 I)
    {
        //Raymarch iterator, step distance, depth and reflection
        float i, d, z, r;
        //Clear fragcolor and raymarch 90 steps
        for(O*= i; i++<9e1;
        //Pick color and attenuate
        O += (cos(z*.5+iTime+vec4(0,2,4,3))+1.3)/d/z)
        {
            //Raymarch sample point
            vec3 p = z * normalize(vec3(I+I,0) - iResolution.xyy);
            //Shift camera and get reflection coordinates
            r = max(-++p, 0.).y;
            //Mirror
            p.y += r+r;
            //Music test
            //-4.*texture(iChannel0, vec2(p.x,-10)/2e1+.5,2.).r
            
            //Sine waves
            for(d=1.; d<3e1; d+=d)
                p.y += cos(p*d+2.*iTime*0.1*cos(d)+z).x/d;
                
            //Step forward (reflections are softer)
            z += d = (.1*r+abs(p.y-1.)/ (1.+r+r+r*r) + max(d=p.z+3.,-d*.1))/8.;
        }
        //Tanh tonemapping
        O = tanh(O/9e2);
    }
    """

    src_messed = """
    // Created by inigo quilez - iq/2013 : https://www.shadertoy.com/view/4dl3zn
    // License Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
    // Messed up by Weyland

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
          vec2 uv = -1.0 + 2.0*fragCoord.xy / iResolution.xy;
          uv.x *=  iResolution.x / iResolution.y;
          vec3 color = vec3(0.0);
          for( int i=0; i<128; i++ )
          {
            float pha =      sin(float(i)*546.13+1.0)*0.5 + 0.5;
            float siz = pow( sin(float(i)*651.74+5.0)*0.5 + 0.5, 4.0 );
            float pox =      sin(float(i)*321.55+4.1) * iResolution.x / iResolution.y;
            float rad = 0.1+0.5*siz+sin(pha+siz)/4.0;
            vec2  pos = vec2( pox+sin(iTime/15.+pha+siz), -1.0-rad + (2.0+2.0*rad)*mod(pha+0.3*(iTime/7.)*(0.2+0.8*siz),1.0));
            float dis = length( uv - pos );
            vec3  col = mix( vec3(0.194*sin(iTime/6.0)+0.3,0.2,0.3*pha), vec3(1.1*sin(iTime/9.0)+0.3,0.2*pha,0.4), 0.5+0.5*sin(float(i)));
            float f = length(uv-pos)/rad;
            f = sqrt(clamp(1.0+(sin((iTime)*siz)*0.5)*f,0.0,1.0));
            color += col.zyx *(1.0-smoothstep( rad*0.15, rad, dis ));
          }
          color *= sqrt(1.5-0.5*length(uv));
          fragColor = vec4(color,1.0);
    }
    """

    src_bokeh = """
    #define S(a, b, t) smoothstep(a,b,t)
    struct ray {
        vec3 o, d;
    };

    ray GetRay(vec2 uv, vec3 camPos, vec3 lookat, float zoom) {
        ray a;
        a.o = camPos;

        vec3 f = normalize(lookat - camPos);
        vec3 r = cross(vec3(0, 1, 0), f);
        vec3 u = cross(f, r);
        vec3 c = a.o + f * zoom;
        vec3 i = c + uv.x * r + uv.y * u;

        a.d = normalize(i - a.o);

        return a;
    }

    float N(float t) {
        return fract(sin(t * 3456.) * 6547.);
    }

    vec4 N14(float t) {
        return fract(sin(t * vec4(123., 1024., 3456., 9564.)) * vec4(6547., 345., 8799., 1564.));
    }

    vec3 ClosestPoint(ray r, vec3 p) {
        return r.o + max(0.0, dot(p - r.o, r.d)) * r.d;
    }

    float DistRay(ray r, vec3 p) {
        return length(p - ClosestPoint(r, p));
    }

    float Bokeh(ray r, vec3 p, float size, float blur) {
        float d = DistRay(r, p);
        size *= length(p);
        float c = S(size, size * (1.0 - blur), d);
        c *= mix(0.7, 1.0, S(size * 0.8, size, d));
        return c;
    }

    vec3 StreetLights(ray r, float t)
    {
        float side = step(r.d.x, 0.);
        r.d.x = abs(r.d.x);
        float s = 0.1;
        float m = 0.;
        for(float i = 0.; i < 1.; i += s)
        {
            float ti = fract(t + i + side * s / 2.);
            vec3 p = vec3(2.0, 2.0, 100. - ti * 100.);
            m += Bokeh(r, p, 0.05, 0.1) * ti * ti * ti;
        }

        return vec3(0.9, 0.7, 0.3) * m;
    }

    vec3 Headlights(ray r, float t)
    {
        t *= 2.0;
        float w1 = 0.25;
        float w2 = w1 * 1.2;
        float s = 0.03;
        float m = 0.;
        for(float i = 0.; i < 1.; i += s)
        {
            float n = N(i);
            if(n > 0.1) continue;

            float ti = fract(t + i );
            float z = 100. - ti * 100.;
            float fade = ti * ti * ti * ti * ti;
            float focus = S(0.9, 1.0, ti);
            float size = mix(0.05, 0.03, focus);

            m += Bokeh(r, vec3(-1.0 - w1, 0.15, z), size, 0.1) * fade;
            m += Bokeh(r, vec3(-1.0 + w1, 0.15, z), size, 0.1) * fade;
            
            m += Bokeh(r, vec3(-1.0 - w2 , 0.15, z), size, 0.1) * fade;
            m += Bokeh(r, vec3(-1.0 + w2, 0.15, z), size, 0.1) * fade;

            float ref = 0.0;
            ref += Bokeh(r, vec3(-1.0 - w2 , -0.15, z), size * 3.0, 1.0) * fade;
            ref += Bokeh(r, vec3(-1.0 + w2, -0.15, z), size * 3.0, 1.0) * fade;

            m += ref * focus;
        }

        return vec3(0.9, 0.9, 1.0) * m;
    }

    vec3 Taillights(ray r, float t)
    {
        t *= 0.25;
        float w1 = 1. / 15.;
        float w2 = w1 * 1.2;
        float s = 0.023;
        float m = 0.;
        for(float i = 0.; i < 1.; i += s)
        {
            float n = N(i);
            if(n > 0.5) continue;

            float lane = step(0.25, n);
            float ti = fract(t + i);
            float z = 100. - ti * 100.;
            float fade = ti * ti * ti * ti * ti * ti * ti * ti * ti;
            float focus = S(0.9, 1.0, ti);
            float size = mix(0.05, 0.03, focus);

            float laneshift = S(1.0, 0.96, ti);
            float x = 1.5 - lane * laneshift;

            float blink = step(0., sin(t * 700.)) * 7. * lane * step(0.96, ti);

            m += Bokeh(r, vec3(x - w1, 0.15, z), size, 0.1) * fade;
            m += Bokeh(r, vec3(x + w1, 0.15, z), size, 0.1) * fade;
            
            m += Bokeh(r, vec3(x - w2 , 0.15, z), size, 0.1) * fade;
            m += Bokeh(r, vec3(x + w2, 0.15, z), size, 0.1) * fade * (1. + blink);

            float ref = 0.0;
            ref += Bokeh(r, vec3(x - w2 , -0.15, z), size * 3.0, 1.0) * fade;
            ref += Bokeh(r, vec3(x + w2, -0.15, z), size * 3.0, 1.0) * fade * (1. + blink * 0.1);

            m += ref * focus;
        }

        return vec3(1.0, 0.1, 0.03) * m;
    }

    vec3 Envlights(ray r, float t)
    {
        float side = step(r.d.x, 0.);
        r.d.x = abs(r.d.x);
        float s = 0.03;
        vec3 c = vec3(0.0);
        for(float i = 0.; i < 1.; i += s)
        {
            float ti = fract(t + i + side * s / 2.);
            vec4 n = N14(i + side * 100.);
            float fade = ti * ti * ti;
            float occlution = sin(ti * 6.28 * 10. * n.x) * 0.5 + 0.5;
            float x = mix(2.5, 10.0, n.x);
            float y = mix(0.1, 1.5, n.y);

            vec3 p = vec3(x, y, 50. - ti * 50.);
            c += Bokeh(r, p, 0.05, 0.1) * fade * n.wzy * occlution;
        }

        return c;
    }

    vec2 Rain(vec2 uv, float t) {
        t *= 20.;
        vec2 a = vec2(3.0, 1.0);
        vec2 st = uv * a;

        vec2 id = floor(st);
        st.y += t * 0.22;
        st.y += fract(sin(id.x * 716.34) * 768.34);
        id = floor(st);
        st = fract(st) - 0.5;
        t += fract(sin(id.x * 76.34 + id.y * 153.7) * 768.34) * 6.28;

        float y = -sin(t + sin(t + sin(t) * 0.5)) * 0.44;
        vec2 p1 = vec2(0.0, y);
        vec2 o1 = (st - p1) / a;

        float d = length(o1);
        float m1 = S(0.07, 0.0, d);

        vec2 o2 = (fract(uv * a.x * vec2(1., 2.)) - 0.5) / vec2(1., 2.);
        d = length(o2);
        float m2 = S(0.3 * (0.5 - st.y), 0.0, d) * S(-0.1, 0.1, st.y - p1.y);

        return vec2(m1 * o1 * 30. + m2 * o2 * 10.);
    }

    void mainImage( out vec4 fragColor, in vec2 fragCoord )
    {
        vec2 uv = fragCoord/iResolution.xy;
        uv -= 0.5;
        uv.x *= iResolution.x / iResolution.y;

        vec2 m = iMouse.xy / iResolution.xy;
        vec3 camPos = vec3(0.5, 0.2, 0);
        vec3 lookat = vec3(0.5, 0.2, 1.0);

        float t = iTime * 0.01 + m.x;

        vec2 rainDistort = Rain(uv * 5., t) * 0.5;
        rainDistort += Rain(uv * 7., t) * 0.5;
        
        uv.x += sin(uv.y * 50.) * 0.001;
        uv.y += sin(uv.x * 121.) * 0.001;
        ray r = GetRay(uv - rainDistort * 0.5, camPos, lookat, 2.0);

        vec3 col = StreetLights(r, t);
        col += Headlights(r, t);
        col += Taillights(r, t);
        col += Envlights(r, t);
        col += (r.d.y + 0.25) * vec3(0.2, 0.1, 0.5);
        //col = vec3(rainDistort, 0.);
        fragColor = vec4(col, 1.0);
    }
    """

    src_test = """
    void mainImage( out vec4 fragColor, in vec2 fragCoord ) {
      fragColor = vec4(0.0, 0.5, 0.8, 1.0);
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
