////
//// Created by גאי ברנשטיין on 28/09/2024.
////
//#include <fstream>
//#include <string>
//#include <iostream>
//
//bool createTestDocx(const std::string& filename, const std::string& content) {
//    std::ofstream file(filename, std::ios::out | std::ios::binary);
//    if (!file) {
//        return false;
//    }
//    file << content;
//    file.close();
//    return true;
//}
//
//// Usage
//int main() {
//    std::string filename = "New_product_spec.txt";
//    std::string content = "The Beatles were an English rock band formed in Liverpool in 1960. The core lineup of the band comprised John Lennon, Paul McCartney, George Harrison and Ringo Starr. They are widely regarded as the most influential band of all time[1] and were integral to the development of 1960s counterculture and the recognition of popular music as an art form.[2] Rooted in skiffle, beat and 1950s rock 'n' roll, their sound incorporated elements of classical music and traditional pop in innovative ways. The band also explored music styles ranging from folk and Indian music to psychedelia and hard rock. As pioneers in recording, songwriting and artistic presentation, the Beatles revolutionized many aspects of the music industry and were often publicized as leaders of the era's youth and sociocultural movements.[3]\n"
//                          "\n"
//                          "Led by primary songwriters Lennon and McCartney, the Beatles evolved from Lennon's previous group, the Quarrymen, and built their reputation by playing clubs in Liverpool and Hamburg, Germany, over three years from 1960, initially with Stuart Sutcliffe playing bass. The core trio of Lennon, McCartney and Harrison, together since 1958, went through a succession of drummers, including Pete Best, before inviting Starr to join them in 1962. Manager Brian Epstein moulded them into a professional act, and producer George Martin guided and developed their recordings, greatly expanding their domestic success after they signed with EMI Records and achieved their first hit, \"Love Me Do\", in late 1962. As their popularity grew into the intense fan frenzy dubbed \"Beatlemania\", the band acquired the nickname \"the Fab Four\". Epstein, Martin or other members of the band's entourage were sometimes informally referred to as a \"fifth Beatle\".\n"
//                          "\n"
//                          "By early 1964, the Beatles were international stars and had achieved unprecedented levels of critical and commercial success. They became a leading force in Britain's cultural resurgence, ushering in the British Invasion of the United States pop market. They soon made their film debut with A Hard Day's Night (1964). A growing desire to refine their studio efforts, coupled with the challenging nature of their concert tours, led to the band's retirement from live performances in 1966. During this time, they produced albums of greater sophistication, including Rubber Soul (1965), Revolver (1966) and Sgt. Pepper's Lonely Hearts Club Band (1967). They enjoyed further commercial success with The Beatles (also known as \"the White Album\", 1968) and Abbey Road (1969). The success of these records heralded the album era, as albums became the dominant form of record use over singles. These records also increased public interest in psychedelic drugs and Eastern spirituality and furthered advancements in electronic music, album art and music videos. In 1968, they founded Apple Corps, a multi-armed multimedia corporation that continues to oversee projects related to the band's legacy. After the group's break-up in 1970, all principal former members enjoyed success as solo artists, and some partial reunions occurred. Lennon was murdered in 1980, and Harrison died of lung cancer in 2001. McCartney and Starr remain musically active.\n"
//                          "\n"
//                          "The Beatles are the best-selling music act of all time, with estimated sales of 600 million units worldwide.[4][5] They are the most successful act in the history of the US Billboard charts,[6] holding the record for most number-one albums on the UK Albums Chart (15), most number-one hits on the US Billboard Hot 100 chart (20), and most singles sold in the UK (21.9 million). The band received many accolades, including seven Grammy Awards, four Brit Awards, an Academy Award (for Best Original Song Score for the 1970 documentary film Let It Be) and fifteen Ivor Novello Awards. They were inducted into the Rock and Roll Hall of Fame in their first year of eligibility, 1988, and each principal member was individually inducted between 1994 and 2015. In 2004 and 2011, the group topped Rolling Stone's lists of the greatest artists in history. Time magazine named them among the 20th century's 100 most important people.";
//    std::string gay;
//    for(int i = 0; i<33 ; i++)
//        gay.append(std::to_string(i));
//    if (createTestDocx(filename, content)) {
//        std::cout << "Test .docx file created successfully." << std::endl;
//    } else {
//        std::cout << "Failed to create test .docx file." << std::endl;
//    }
//    return 0;
//}