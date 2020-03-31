
#ifndef __WAVE_STRUCT_H_
#define __WAVE_STRUCT_H_

#define FOURCC unsigned int 

#define WAVE_HEAD_SIZE 36

#define MAKE_FOURCC(a,b,c,d) \
( ((unsigned int)a) | ( ((unsigned int)b) << 8 ) | ( ((unsigned int)c) << 16 ) | ( ((unsigned int)d) << 24 ) )

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct 
{
    FOURCC ChunkID;    //内容为"RIFF"
    unsigned int ChunkSize;    //存储文件的字节数（不包含ChunkID和ChunkSize这8个字节）
    FOURCC Format;    //内容为"WAVE"
}WAVE_HEADER;

typedef struct 
{
    FOURCC Subchunk1ID;    //内容为"fmt"
    unsigned int Subchunk1Size;    //存储该WAVE_FMT子块的字节数（不含前面的Subchunk1ID和Subchunk1Size这8个字节）
    unsigned short AudioFormat;    //存储音频文件的编码格式，例如若为PCM则其存储值为1，若为其他非PCM格式的则有一定的压缩。
    unsigned short NumChannels;    //通道数，单通道(Mono)值为1，双通道(Stereo)值为2，等等
    unsigned int SampleRate;    //采样率，如8k，44.1k等
    unsigned int ByteRate;    //每秒存储的bit数，其值=SampleRate * NumChannels * BitsPerSample/8
    unsigned short BlockAlign;    //块对齐大小，其值=NumChannels * BitsPerSample/8
    unsigned short BitsPerSample;    //每个采样点的bit数，一般为8,16,32等。
}WAVE_FMT;

typedef struct 
{
    FOURCC Subchunk2ID;    //内容为“data”
    unsigned int Subchunk2Size;    //内容为接下来的正式的数据部分的字节数，其值=NumSamples * NumChannels * BitsPerSample/8
}WAVE_DATA;

//pcm转wav
/********************************************************
   Func Name: pcm_to_wave
Date Created: 2019-2-23
 Description: pcm转wav
       Input:
      Output:
      Return: wave文件大小
     Caution: audioData指向的内存空间需要单独释放
*********************************************************/

int pcm_to_wave(unsigned short channel
    , unsigned int rate
    , unsigned short bits
    , unsigned char *pcmData
    , unsigned int pcmSize
    , unsigned char ** audioData);

#ifdef __cplusplus
}
#endif

#endif
