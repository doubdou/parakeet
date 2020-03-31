
#include "audioparse/wave_struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/********************************************************
   Func Name: pcm_to_wave
Date Created: 2019-2-23
 Description: pcm转wav
       Input:
      Output:
      Return: wave文件大小
     Caution:
*********************************************************/
int pcm_to_wave(unsigned short channel
    , unsigned int rate
    , unsigned short bits
    , unsigned char *pcmData
    , unsigned int pcmSize
    , unsigned char ** audioData)
{
    WAVE_HEADER wavHeader;
    WAVE_FMT wavFmt;
    WAVE_DATA wavData;
    unsigned char * outData = NULL;
    int outSize = 0;

    //1.参数校验
    if (NULL == pcmData || NULL == audioData)
    {
        return 0;
    }

    //2.文件头赋值

    //第一部分
    wavHeader.ChunkID = MAKE_FOURCC('R', 'I', 'F', 'F');
    wavHeader.ChunkSize = WAVE_HEAD_SIZE + pcmSize;
    wavHeader.Format = MAKE_FOURCC('W', 'A', 'V', 'E');

    //第二部分
    wavFmt.Subchunk1ID = MAKE_FOURCC('f', 'm', 't', ' ');
    wavFmt.Subchunk1Size = 16;
    wavFmt.AudioFormat = 0x01;
    wavFmt.NumChannels = channel;
    wavFmt.SampleRate = rate;
    wavFmt.ByteRate = channel * rate * bits / 8;
    wavFmt.BlockAlign = channel * rate / 8;
    wavFmt.BitsPerSample = bits;

    //第三部分
    wavData.Subchunk2ID = MAKE_FOURCC('d', 'a', 't', 'a');
    wavData.Subchunk2Size = pcmSize;


    //数据输出
    outSize = wavHeader.ChunkSize + sizeof(wavHeader.ChunkID) + sizeof(wavHeader.ChunkSize);
    outData = (unsigned char *)calloc(1, outSize);
    if (NULL == outData)
    {
        return 0;
    }
    //拷贝第一部分
    memcpy(outData, &wavHeader, sizeof(wavHeader));

    //拷贝第二部分
    memcpy(outData + sizeof(wavHeader), &wavFmt, sizeof(wavFmt));

    //拷贝第三部分
    memcpy(outData + sizeof(wavHeader) + sizeof(wavFmt), &wavData, sizeof(wavData));

    //拷贝pcm数据
    memcpy(outData + sizeof(wavHeader) + sizeof(wavFmt) + sizeof(wavData), pcmData, pcmSize);

    *audioData = outData;

    return outSize;

}
